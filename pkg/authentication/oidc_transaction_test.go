package authentication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestOIDCTransactionSessionDecodesCorruptTransaction(t *testing.T) {
	store := testSessionStore(t)
	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/callback", nil)
	rec := httptest.NewRecorder()
	session, err := store.Get(req, auth.OIDCAuthSessionName)
	require.NoError(t, err)
	session.Values[oidcTransactionSessionKey] = "{not-json"
	require.NoError(t, session.Save(req, rec))

	nextReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/callback", nil)
	for _, cookie := range rec.Result().Cookies() {
		nextReq.AddCookie(cookie)
	}
	oidcSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), nextReq)
	require.NoError(t, err)
	_, err = oidcSession.Transaction()
	require.Error(t, err)
}

func TestOIDCTransactionClearPersistsDeletion(t *testing.T) {
	store := testSessionStore(t)
	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	rec := httptest.NewRecorder()
	require.NoError(t, (oidcSessionStore{store: store}).SaveTransaction(rec, req, sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/")))

	callbackReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/callback", nil)
	for _, cookie := range rec.Result().Cookies() {
		callbackReq.AddCookie(cookie)
	}
	clearRec := httptest.NewRecorder()
	oidcSession, err := (oidcSessionStore{store: store}).Load(clearRec, callbackReq)
	require.NoError(t, err)
	require.NoError(t, oidcSession.ClearTransactionAndSave())

	afterReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/callback", nil)
	for _, cookie := range clearRec.Result().Cookies() {
		afterReq.AddCookie(cookie)
	}
	afterSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), afterReq)
	require.NoError(t, err)
	_, err = afterSession.Transaction()
	require.Error(t, err)
}

func TestSaveTransactionReplacesCorruptOIDCCookie(t *testing.T) {
	store := testSessionStore(t)
	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	req.AddCookie(&http.Cookie{Name: auth.OIDCAuthSessionName, Value: strings.Repeat("x", 32)})
	rec := httptest.NewRecorder()

	transaction := sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/repositories")
	require.NoError(t, (oidcSessionStore{store: store}).SaveTransaction(rec, req, transaction))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, auth.OIDCAuthSessionName, cookies[0].Name)

	nextReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/oidc/callback", nil)
	nextReq.AddCookie(cookies[0])
	oidcSession, err := (oidcSessionStore{store: store}).Load(httptest.NewRecorder(), nextReq)
	require.NoError(t, err)
	got, err := oidcSession.Transaction()
	require.NoError(t, err)
	require.Equal(t, transaction.StateValue, got.StateValue)
	require.Equal(t, transaction.Next, got.Next)
}

func TestOIDCTransactionValidation(t *testing.T) {
	transaction := sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/")
	require.NoError(t, transaction.validateCallbackState("state-1", time.Now()))
	require.Error(t, transaction.validateCallbackState("wrong", time.Now()))

	expired := *transaction
	expired.StartedAt = time.Now().Add(-oidcTransactionTTL - time.Second).Unix()
	require.Error(t, expired.validateCallbackState("state-1", time.Now()))
}

func TestOIDCSaveClaimsEnforcesSizeLimit(t *testing.T) {
	store := testSessionStore(t)
	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/callback", nil)
	rec := httptest.NewRecorder()
	oidcSession, err := (oidcSessionStore{store: store}).Load(rec, req)
	require.NoError(t, err)

	err = oidcSession.SaveClaims(encoding.Claims{
		"sub":   "alice",
		"large": strings.Repeat("x", oidcClaimsMaxJSONSize),
	}, time.Now().Add(time.Hour))
	require.Error(t, err)
}

func TestOIDCSessionSaveClaimsWritesCurrentAuthSchema(t *testing.T) {
	store := testSessionStore(t)
	saveReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/callback", nil)
	rec := httptest.NewRecorder()
	oidcSession, err := (oidcSessionStore{store: store}).Load(rec, saveReq)
	require.NoError(t, err)
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	require.NoError(t, oidcSession.SaveClaims(encoding.Claims{"iss": "https://issuer.example", "sub": "alice"}, expiresAt))

	loadReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/repositories", nil)
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	loadReq.AddCookie(cookies[0])
	loadedSession, err := store.Get(loadReq, auth.OIDCAuthSessionName)
	require.NoError(t, err)
	loadedExpiresAt, ok := loadedSession.Values["_lakefs_oidc_claims_expires_at"].(int64)
	require.True(t, ok)
	require.Equal(t, expiresAt.Unix(), loadedExpiresAt)

	externalID := "alice"
	user, err := auth.UserFromOIDCSession(t.Context(), logging.Dummy(), &oidcRequestAuthService{
		user: &model.User{
			CreatedAt:  time.Now().UTC(),
			Username:   "alice",
			ExternalID: &externalID,
			Source:     "oidc",
		},
	}, loadedSession, &auth.OIDCConfig{})
	require.NoError(t, err)
	require.Equal(t, "alice", user.Username)
}

type oidcRequestAuthService struct {
	auth.Service
	user *model.User
}

func (s *oidcRequestAuthService) GetUserByExternalID(_ context.Context, externalID string) (*model.User, error) {
	if s.user == nil || s.user.ExternalID == nil || *s.user.ExternalID != externalID {
		return nil, auth.ErrNotFound
	}
	return s.user, nil
}
