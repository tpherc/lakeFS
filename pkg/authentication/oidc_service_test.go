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
	"github.com/treeverse/lakefs/pkg/auth/model"
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
	authService := newOIDCCallbackAuthService()
	service := testOIDCServiceWithAuth(fakeClient, config.OIDC{
		FriendlyNameClaimName:  "name",
		EmailClaimName:         "email",
		InitialGroupsClaimName: "groups",
		ValidateIDTokenClaims:  map[string]string{"department": "Data"},
	}, authService)

	callbackURL := "https://lakefs.example/api/v1/oidc/callback?state=state-1&code=code-1"
	callbackReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	for _, cookie := range latestCookies(loginRec.Result()) {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()

	service.OauthCallback(callbackRec, callbackReq, store)
	require.Equal(t, http.StatusFound, callbackRec.Code)
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
		"name":       "Alice",
		"department": "Data",
	}, claims)
	require.Len(t, authService.createdUsers, 1)
	require.Equal(t, "alice@example.com", stringValue(authService.createdUsers[0].Email))
	require.Equal(t, []oidcCallbackGroupMembership{
		{username: authService.createdUsers[0].Username, groupID: "Developers"},
		{username: authService.createdUsers[0].Username, groupID: "Readers"},
	}, authService.addedGroups)

	replayReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	for _, cookie := range latestCookies(callbackRec.Result()) {
		replayReq.AddCookie(cookie)
	}
	replayRec := httptest.NewRecorder()
	service.OauthCallback(replayRec, replayReq, store)
	require.Equal(t, http.StatusFound, replayRec.Code)
	require.Equal(t, "/auth/login", replayRec.Header().Get("Location"))
	require.Equal(t, 1, fakeClient.exchangeCalls)
}

func TestOIDCCallbackRequiredClaimMismatchDoesNotSaveSessionOrProvisionUser(t *testing.T) {
	store := testSessionStore(t)
	transaction := sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/repositories")
	loginReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	loginRec := httptest.NewRecorder()
	require.NoError(t, (oidcSessionStore{store: store}).SaveTransaction(loginRec, loginReq, transaction))

	authService := newOIDCCallbackAuthService()
	fakeClient := &fakeOIDCClient{
		exchangeFunc: func(_ context.Context, _ *oidcTransaction, _ oidcCallbackInput) (encoding.Claims, error) {
			return encoding.Claims{
				"iss":        "https://idp.example",
				"sub":        "alice",
				"department": "Finance",
			}, nil
		},
	}
	service := testOIDCServiceWithAuth(fakeClient, config.OIDC{
		ValidateIDTokenClaims: map[string]string{"department": "Data"},
	}, authService)

	callbackReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/oidc/callback?state=state-1&code=code-1", nil)
	for _, cookie := range latestCookies(loginRec.Result()) {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()

	service.OauthCallback(callbackRec, callbackReq, store)
	require.Equal(t, http.StatusFound, callbackRec.Code)
	require.Equal(t, "/auth/login", callbackRec.Header().Get("Location"))
	require.Empty(t, authService.createdUsers)

	afterReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/repositories", nil)
	for _, cookie := range latestCookies(callbackRec.Result()) {
		afterReq.AddCookie(cookie)
	}
	oidcSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), afterReq)
	require.NoError(t, err)
	_, hasClaims := oidcSession.session.Values[auth.IDTokenClaimsSessionKey]
	require.False(t, hasClaims)
}

func TestOIDCCallbackExistingUserIgnoresLargeCreationOnlyGroupClaim(t *testing.T) {
	store := testSessionStore(t)
	transaction := sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/repositories")
	loginReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	loginRec := httptest.NewRecorder()
	require.NoError(t, (oidcSessionStore{store: store}).SaveTransaction(loginRec, loginReq, transaction))

	externalID := oidcExternalIDForTest("https://idp.example", "alice")
	authService := newOIDCCallbackAuthService(&model.User{
		Username:   "alice",
		ExternalID: stringPtr(externalID),
		Source:     "oidc",
	})
	fakeClient := &fakeOIDCClient{
		exchangeFunc: func(_ context.Context, _ *oidcTransaction, _ oidcCallbackInput) (encoding.Claims, error) {
			return encoding.Claims{
				"iss":    "https://idp.example",
				"sub":    "alice",
				"name":   "Alice",
				"groups": strings.Repeat("x", oidcClaimsMaxJSONSize*2),
			}, nil
		},
	}
	service := testOIDCServiceWithAuth(fakeClient, config.OIDC{
		FriendlyNameClaimName:  "name",
		InitialGroupsClaimName: "groups",
		PersistFriendlyName:    true,
	}, authService)

	callbackReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/oidc/callback?state=state-1&code=code-1", nil)
	for _, cookie := range latestCookies(loginRec.Result()) {
		callbackReq.AddCookie(cookie)
	}
	callbackRec := httptest.NewRecorder()

	service.OauthCallback(callbackRec, callbackReq, store)
	require.Equal(t, http.StatusFound, callbackRec.Code)
	require.Equal(t, "/repositories", callbackRec.Header().Get("Location"))
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
	require.Equal(t, []oidcCallbackFriendlyNameUpdate{{username: "alice", friendlyName: "Alice"}}, authService.friendlyNameUpdates)

	authedReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/repositories", nil)
	for _, cookie := range latestCookies(callbackRec.Result()) {
		authedReq.AddCookie(cookie)
	}
	oidcSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), authedReq)
	require.NoError(t, err)
	claimsJSON, ok := oidcSession.session.Values[auth.IDTokenClaimsSessionKey].(string)
	require.True(t, ok)
	var claims encoding.Claims
	require.NoError(t, json.Unmarshal([]byte(claimsJSON), &claims))
	require.NotContains(t, claims, "groups")
	require.Equal(t, "Alice", claims["name"])
}

func TestOIDCCallbackWrongStateClearsTransaction(t *testing.T) {
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
	require.Equal(t, http.StatusFound, callbackRec.Code)
	require.NotEmpty(t, callbackRec.Result().Cookies())

	afterReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/oidc/callback", nil)
	for _, cookie := range latestCookies(callbackRec.Result()) {
		afterReq.AddCookie(cookie)
	}
	afterSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), afterReq)
	require.NoError(t, err)
	_, err = afterSession.Transaction()
	require.Error(t, err)
}

func TestNormalizeOIDCClaimsRequiresSubject(t *testing.T) {
	_, err := normalizeOIDCClaims(encoding.Claims{"iss": "https://idp.example"}, config.OIDC{})
	require.Error(t, err)
}

func TestNormalizeOIDCClaimsRequiresIssuer(t *testing.T) {
	_, err := normalizeOIDCClaims(encoding.Claims{"sub": "alice"}, config.OIDC{})
	require.Error(t, err)
}

func TestNewOIDCServiceRejectsInvalidLogoutURLBeforeProviderInitialization(t *testing.T) {
	service, err := NewOIDCService(t.Context(), nil, config.OIDCProvider{}, config.OIDC{}, time.Hour, "logout", logging.ContextUnavailable())
	require.Error(t, err)
	require.Nil(t, service)
}

func testOIDCService(client oidcProtocolClient, claimsConfig config.OIDC) *OIDCService {
	return testOIDCServiceWithAuth(client, claimsConfig, newOIDCCallbackAuthService())
}

func testOIDCServiceWithAuth(client oidcProtocolClient, claimsConfig config.OIDC, authService auth.Service) *OIDCService {
	callbacks, err := newOIDCCallbackResolver(config.OIDCProvider{CallbackBaseURL: "https://lakefs.example"})
	if err != nil {
		panic(err)
	}
	return &OIDCService{
		oidc:                 client,
		callbacks:            callbacks,
		authService:          authService,
		userClaimsConfig:     claimsConfig,
		sessionDuration:      time.Hour,
		logger:               logging.ContextUnavailable(),
		postLoginRedirectURL: "",
		logoutRedirectURL:    "/auth/login",
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

type oidcCallbackAuthService struct {
	auth.Service
	usersByExternalID   map[string]*model.User
	createdUsers        []*model.User
	addedGroups         []oidcCallbackGroupMembership
	friendlyNameUpdates []oidcCallbackFriendlyNameUpdate
	deletedUsers        []string
	addUserToGroupErr   error
	deleteUserErr       error
}

type oidcCallbackGroupMembership struct {
	username string
	groupID  string
}

type oidcCallbackFriendlyNameUpdate struct {
	username     string
	friendlyName string
}

func newOIDCCallbackAuthService(users ...*model.User) *oidcCallbackAuthService {
	s := &oidcCallbackAuthService{usersByExternalID: make(map[string]*model.User)}
	for _, user := range users {
		if user.ExternalID != nil {
			s.usersByExternalID[*user.ExternalID] = cloneUser(user)
		}
	}
	return s
}

func (s *oidcCallbackAuthService) GetUserByExternalID(_ context.Context, externalID string) (*model.User, error) {
	user := s.usersByExternalID[externalID]
	if user == nil {
		return nil, auth.ErrNotFound
	}
	return cloneUser(user), nil
}

func (s *oidcCallbackAuthService) CreateUser(_ context.Context, user *model.User) (string, error) {
	copied := cloneUser(user)
	s.createdUsers = append(s.createdUsers, copied)
	if copied.ExternalID != nil {
		s.usersByExternalID[*copied.ExternalID] = cloneUser(copied)
	}
	return user.Username, nil
}

func (s *oidcCallbackAuthService) AddUserToGroup(_ context.Context, username, groupID string) error {
	s.addedGroups = append(s.addedGroups, oidcCallbackGroupMembership{username: username, groupID: groupID})
	return s.addUserToGroupErr
}

func (s *oidcCallbackAuthService) DeleteUser(_ context.Context, username string) error {
	s.deletedUsers = append(s.deletedUsers, username)
	if s.deleteUserErr != nil {
		return s.deleteUserErr
	}
	for externalID, user := range s.usersByExternalID {
		if user.Username == username {
			delete(s.usersByExternalID, externalID)
		}
	}
	return nil
}

func (s *oidcCallbackAuthService) UpdateUserFriendlyName(_ context.Context, username, friendlyName string) error {
	s.friendlyNameUpdates = append(s.friendlyNameUpdates, oidcCallbackFriendlyNameUpdate{
		username:     username,
		friendlyName: friendlyName,
	})
	for _, user := range s.usersByExternalID {
		if user.Username == username {
			user.FriendlyName = &friendlyName
		}
	}
	return nil
}

func cloneUser(user *model.User) *model.User {
	if user == nil {
		return nil
	}
	copied := *user
	return &copied
}

func stringPtr(value string) *string {
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

type fakeOIDCClient struct {
	beginFunc     func(context.Context, oidcBeginLoginInput) (*oidcTransaction, string, error)
	exchangeFunc  func(context.Context, *oidcTransaction, oidcCallbackInput) (encoding.Claims, error)
	beginCalls    int
	exchangeCalls int
	closeCalled   bool
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
