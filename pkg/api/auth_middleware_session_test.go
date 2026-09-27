package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestOIDCSessionReissueOnlyWhenEncodingUpgradeNeeded(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	store, err := auth.NewSessionStore(secret, auth.SessionStoreOptions{MaxAge: 3600})
	require.NoError(t, err)
	username := "oidc-user"
	externalID := oidcExternalIDForTest("https://issuer.example", username)
	authService := oidcMiddlewareAuthService{
		user: &model.User{
			Username:   username,
			ExternalID: &externalID,
			Source:     "oidc",
		},
	}
	securityRequirements := openapi3.SecurityRequirements{
		{"oidc_auth": []string{}},
	}

	t.Run("historical OIDC cookie is rejected and expired", func(t *testing.T) {
		legacyStore := sessions.NewCookieStore(secret)
		req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		rec := httptest.NewRecorder()
		session, err := legacyStore.Get(req, auth.OIDCAuthSessionName)
		require.NoError(t, err)
		session.Values[auth.IDTokenClaimsSessionKey] = `{"sub":"oidc-user"}`
		require.NoError(t, session.Save(req, rec))

		gotReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		gotReq.AddCookie(responseCookieByName(t, rec.Result(), auth.OIDCAuthSessionName))
		gotRec := httptest.NewRecorder()

		user, err := checkSecurityRequirements(gotRec, gotReq, securityRequirements, logging.ContextUnavailable(), nil, authService, newMiddlewareProvisioner(t, authService), store, &auth.OIDCConfig{}, nil)
		require.Error(t, err, "expected historical OIDC cookie to fail authentication")
		require.Nil(t, user, "unexpected user: %#v", user)
		require.NotNil(t, responseCookieByName(t, gotRec.Result(), auth.OIDCAuthSessionName), "expected historical OIDC cookie to be expired")
	})

	t.Run("current cookie does not reissue", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		rec := httptest.NewRecorder()
		session, err := store.Get(req, auth.OIDCAuthSessionName)
		require.NoError(t, err)
		session.Values[auth.IDTokenClaimsSessionKey] = `{"iss":"https://issuer.example","sub":"oidc-user"}`
		auth.MarkOIDCSessionClaimsCurrent(session, time.Now().Add(time.Hour))
		require.NoError(t, auth.SaveSession(req, rec, session))

		gotReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		gotReq.AddCookie(responseCookieByName(t, rec.Result(), auth.OIDCAuthSessionName))
		gotRec := httptest.NewRecorder()

		user, err := checkSecurityRequirements(gotRec, gotReq, securityRequirements, logging.ContextUnavailable(), nil, authService, newMiddlewareProvisioner(t, authService), store, &auth.OIDCConfig{}, nil)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.Equal(t, username, user.User.Username)
		require.Nil(t, responseCookieByName(t, gotRec.Result(), auth.OIDCAuthSessionName), "current OIDC cookie must not be reissued")
	})
}

type oidcMiddlewareAuthService struct {
	auth.Service
	user *model.User
}

func (s oidcMiddlewareAuthService) GetUserByExternalID(_ context.Context, externalID string) (*model.User, error) {
	if s.user != nil && s.user.ExternalID != nil && *s.user.ExternalID == externalID {
		return s.user, nil
	}
	return nil, auth.ErrNotFound
}

func responseCookieByName(t testing.TB, response *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
