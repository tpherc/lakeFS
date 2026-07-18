package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestSafePostLoginRedirect(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "login page loop", raw: "/auth/login"},
		{name: "login page loop with query", raw: "/auth/login?x=1"},
		{name: "OIDC login loop", raw: OIDCLoginPath},
		{name: "OIDC callback loop", raw: oidcCallbackPath},
		{name: "valid path", raw: "/repositories/repo/objects?prefix=data#files", want: "/repositories/repo/objects?prefix=data#files"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, safePostLoginRedirect(tt.raw))
		})
	}
}

func TestOIDCLoginUsesProtocolClientAndSavesTransaction(t *testing.T) {
	store := testSessionStore(t)
	fakeClient := &fakeOIDCClient{
		beginFunc: func(_ context.Context, input oidcBeginLoginInput) (*oidcTransaction, string, error) {
			require.Equal(t, "https://lakefs.example/api/v1/oidc/callback", input.CallbackURL)
			require.Equal(t, "/repositories", input.Next)
			return sampleOIDCTransaction(input.CallbackURL, input.Next), "https://idp.example/authorize?state=state-1", nil
		},
	}
	service := testOIDCService(fakeClient, config.OIDC{})

	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login?next=/repositories", nil)
	rec := httptest.NewRecorder()
	service.loginHandler(store).ServeHTTP(rec, req)

	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	require.Equal(t, "https://idp.example/authorize?state=state-1", rec.Header().Get("Location"))
	require.Equal(t, 1, fakeClient.beginCalls)

	setCookie := strings.Join(rec.Header().Values("Set-Cookie"), "\n")
	require.Contains(t, setCookie, auth.InternalAuthSessionName+"=")
	require.Contains(t, setCookie, auth.SAMLAuthSessionName+"=")

	sessionReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/oidc/callback", nil)
	for _, cookie := range latestCookies(rec.Result()) {
		sessionReq.AddCookie(cookie)
	}
	oidcSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), sessionReq)
	require.NoError(t, err)
	transaction, err := oidcSession.Transaction()
	require.NoError(t, err)
	require.Equal(t, "state-1", transaction.StateValue)
	require.Equal(t, "/repositories", transaction.Next)
}

func TestOIDCLoginStopsWhenExistingSessionCleanupFails(t *testing.T) {
	store := &recordingSessionStore{
		getErrors: map[string]error{
			auth.SAMLAuthSessionName: errors.New("saml store failure"),
		},
	}
	fakeClient := &fakeOIDCClient{}
	service := testOIDCService(fakeClient, config.OIDC{})

	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login?next=/repositories", nil)
	rec := httptest.NewRecorder()
	service.loginHandler(store).ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, 0, fakeClient.beginCalls)
	require.Equal(t, []string{auth.InternalAuthSessionName, auth.SAMLAuthSessionName}, store.gets)
	require.Equal(t, []string{auth.InternalAuthSessionName}, store.saves)
}

func TestOIDCCallbackConsumesTransactionBeforeExchangeAndStoresNormalizedClaims(t *testing.T) {
	store := testSessionStore(t)
	transaction := sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/repositories")
	loginReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	loginRec := httptest.NewRecorder()
	require.NoError(t, (oidcSessionStore{store: store}).SaveTransaction(loginRec, loginReq, transaction))

	fakeClient := &fakeOIDCClient{
		exchangeFunc: func(_ context.Context, got *oidcTransaction, input oidcCallbackInput) (encoding.Claims, error) {
			require.Equal(t, transaction.StateValue, got.StateValue)
			require.Equal(t, oidcCallbackInput{State: "state-1", Code: "code-1"}, input)
			return encoding.Claims{
				"iss":        "https://idp.example",
				"sub":        "alice",
				"email":      "alice@example.com",
				"name":       "Alice",
				"groups":     []any{"Developers", "Readers"},
				"department": "Data",
				"extra":      "not stored",
			}, nil
		},
	}
	service := testOIDCService(fakeClient, config.OIDC{
		FriendlyNameClaimName:  "name",
		EmailClaimName:         "email",
		InitialGroupsClaimName: "groups",
		ValidateIDTokenClaims:  map[string]string{"department": "Data"},
	})

	callbackURL := "https://lakefs.example/api/v1/oidc/callback?state=state-1&code=code-1"
	callbackReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	for _, cookie := range latestCookies(loginRec.Result()) {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()

	service.OauthCallback(callbackRec, callbackReq, store)
	require.Equal(t, http.StatusTemporaryRedirect, callbackRec.Code)
	require.Equal(t, "/repositories", callbackRec.Header().Get("Location"))
	require.Equal(t, 1, fakeClient.exchangeCalls)

	authedReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/repositories", nil)
	for _, cookie := range latestCookies(callbackRec.Result()) {
		authedReq.AddCookie(cookie)
	}
	oidcSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), authedReq)
	require.NoError(t, err)
	_, err = oidcSession.Transaction()
	require.Error(t, err)

	claimsJSON, ok := oidcSession.session.Values[auth.IDTokenClaimsSessionKey].(string)
	require.True(t, ok)
	var claims encoding.Claims
	require.NoError(t, json.Unmarshal([]byte(claimsJSON), &claims))
	require.Equal(t, encoding.Claims{
		"iss":        "https://idp.example",
		"sub":        "alice",
		"email":      "alice@example.com",
		"name":       "Alice",
		"groups":     []any{"Developers", "Readers"},
		"department": "Data",
	}, claims)

	replayReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	for _, cookie := range latestCookies(callbackRec.Result()) {
		replayReq.AddCookie(cookie)
	}
	replayRec := httptest.NewRecorder()
	service.OauthCallback(replayRec, replayReq, store)
	require.Equal(t, http.StatusTemporaryRedirect, replayRec.Code)
	require.Equal(t, "/auth/login", replayRec.Header().Get("Location"))
	require.Equal(t, 1, fakeClient.exchangeCalls)
}

func TestOIDCCallbackWrongStateRetainsTransaction(t *testing.T) {
	store := testSessionStore(t)
	transaction := sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/repositories")
	loginReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	loginRec := httptest.NewRecorder()
	require.NoError(t, (oidcSessionStore{store: store}).SaveTransaction(loginRec, loginReq, transaction))

	service := testOIDCService(&fakeOIDCClient{}, config.OIDC{})
	callbackReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/oidc/callback?state=wrong&code=code-1", nil)
	for _, cookie := range latestCookies(loginRec.Result()) {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()

	service.OauthCallback(callbackRec, callbackReq, store)
	require.Equal(t, http.StatusTemporaryRedirect, callbackRec.Code)
	require.Empty(t, callbackRec.Result().Cookies())
}

func TestNormalizeOIDCClaimsRequiresSubject(t *testing.T) {
	_, err := normalizeOIDCClaims(encoding.Claims{"iss": "https://idp.example"}, config.OIDC{})
	require.Error(t, err)
}

func testOIDCService(client oidcProtocolClient, claimsConfig config.OIDC) *OIDCService {
	callbacks, err := newOIDCCallbackResolver(config.OIDCProvider{CallbackBaseURL: "https://lakefs.example"})
	if err != nil {
		panic(err)
	}
	return &OIDCService{
		oidc:                 client,
		callbacks:            callbacks,
		userClaimsConfig:     claimsConfig,
		logger:               logging.ContextUnavailable(),
		postLoginRedirectURL: "",
	}
}

func testSessionStore(t *testing.T) *sessions.CookieStore {
	t.Helper()
	store, err := auth.NewSessionStore([]byte("0123456789abcdef0123456789abcdef"), auth.SessionStoreOptions{
		MaxAge: 3600,
		Secure: true,
	})
	require.NoError(t, err)
	return store
}

func latestCookies(response *http.Response) []*http.Cookie {
	byName := make(map[string]*http.Cookie)
	order := make([]string, 0)
	for _, cookie := range response.Cookies() {
		if _, ok := byName[cookie.Name]; !ok {
			order = append(order, cookie.Name)
		}
		byName[cookie.Name] = cookie
	}
	cookies := make([]*http.Cookie, 0, len(order))
	for _, name := range order {
		cookies = append(cookies, byName[name])
	}
	return cookies
}

func sampleOIDCTransaction(redirectURI, next string) *oidcTransaction {
	return &oidcTransaction{
		StateValue:   "state-1",
		NonceValue:   "nonce-1",
		RedirectURI:  redirectURI,
		Next:         next,
		CodeVerifier: "verifier-1",
		StartedAt:    time.Now().Add(-time.Minute).Unix(),
	}
}

type fakeOIDCClient struct {
	beginFunc          func(context.Context, oidcBeginLoginInput) (*oidcTransaction, string, error)
	exchangeFunc       func(context.Context, *oidcTransaction, oidcCallbackInput) (encoding.Claims, error)
	endSessionEndpoint string
	beginCalls         int
	exchangeCalls      int
	closeCalled        bool
}

func (f *fakeOIDCClient) BeginLogin(ctx context.Context, input oidcBeginLoginInput) (*oidcTransaction, string, error) {
	f.beginCalls++
	if f.beginFunc == nil {
		return nil, "", errors.New("unexpected BeginLogin")
	}
	return f.beginFunc(ctx, input)
}

func (f *fakeOIDCClient) Exchange(ctx context.Context, transaction *oidcTransaction, input oidcCallbackInput) (encoding.Claims, error) {
	f.exchangeCalls++
	if f.exchangeFunc == nil {
		return nil, errors.New("unexpected Exchange")
	}
	return f.exchangeFunc(ctx, transaction, input)
}

func (f *fakeOIDCClient) EndSessionEndpoint() string {
	return f.endSessionEndpoint
}

func (f *fakeOIDCClient) Close() {
	f.closeCalled = true
}

type recordingSessionStore struct {
	getErrors  map[string]error
	saveErrors map[string]error
	gets       []string
	saves      []string
}

func (s *recordingSessionStore) Get(_ *http.Request, name string) (*sessions.Session, error) {
	s.gets = append(s.gets, name)
	if err := s.getErrors[name]; err != nil {
		return nil, err
	}
	return sessions.NewSession(s, name), nil
}

func (s *recordingSessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return s.Get(r, name)
}

func (s *recordingSessionStore) Save(_ *http.Request, _ http.ResponseWriter, session *sessions.Session) error {
	name := session.Name()
	s.saves = append(s.saves, name)
	if err := s.saveErrors[name]; err != nil {
		return err
	}
	return nil
}
