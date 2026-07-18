package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/model"
	oidcencoding "github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestCheckSecurityRequirementsContinuesPastCorruptCookieSessions(t *testing.T) {
	store := newMiddlewareSessionStore(t)

	tests := []struct {
		name             string
		corruptSession   string
		validSession     *http.Cookie
		requirements     openapi3.SecurityRequirements
		expectedUser     string
		expiredSession   string
		oidcConfig       *auth.OIDCConfig
		cookieAuthConfig *auth.CookieAuthConfig
	}{
		{
			name:           "corrupt internal cookie with valid OIDC cookie",
			corruptSession: auth.InternalAuthSessionName,
			validSession:   oidcSessionCookie(t, store, "oidc-user", true),
			requirements:   authSecurityRequirements("cookie_auth", "oidc_auth"),
			expectedUser:   "oidc-user",
			expiredSession: auth.InternalAuthSessionName,
			oidcConfig:     &auth.OIDCConfig{},
		},
		{
			name:             "corrupt internal cookie with valid SAML cookie",
			corruptSession:   auth.InternalAuthSessionName,
			validSession:     samlSessionCookie(t, store, "saml-user"),
			requirements:     authSecurityRequirements("cookie_auth", "saml_auth"),
			expectedUser:     "saml-user",
			expiredSession:   auth.InternalAuthSessionName,
			cookieAuthConfig: samlCookieAuthConfig(),
		},
		{
			name:             "corrupt OIDC cookie with valid SAML cookie",
			corruptSession:   auth.OIDCAuthSessionName,
			validSession:     samlSessionCookie(t, store, "saml-user"),
			requirements:     authSecurityRequirements("oidc_auth", "saml_auth"),
			expectedUser:     "saml-user",
			expiredSession:   auth.OIDCAuthSessionName,
			oidcConfig:       &auth.OIDCConfig{},
			cookieAuthConfig: samlCookieAuthConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
			req.AddCookie(&http.Cookie{Name: tt.corruptSession, Value: "corrupt"})
			req.AddCookie(tt.validSession)
			rec := httptest.NewRecorder()
			authService := newMiddlewareAuthService(tt.expectedUser)

			user, err := checkSecurityRequirements(rec, req, tt.requirements, logging.Dummy(), nil, authService, store, tt.oidcConfig, tt.cookieAuthConfig)

			require.NoError(t, err)
			require.Equal(t, tt.expectedUser, user.Username)
			requireSessionExpired(t, rec.Result().Cookies(), tt.expiredSession)
		})
	}
}

func TestCheckSecurityRequirementsReturnsRememberedCookieFailure(t *testing.T) {
	store := newMiddlewareSessionStore(t)
	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.AddCookie(&http.Cookie{Name: auth.InternalAuthSessionName, Value: "corrupt"})
	rec := httptest.NewRecorder()

	user, err := checkSecurityRequirements(rec, req, authSecurityRequirements("cookie_auth", "oidc_auth"), logging.Dummy(), nil, newMiddlewareAuthService(), store, &auth.OIDCConfig{}, nil)

	require.Nil(t, user)
	require.Error(t, err)
	requireSessionExpired(t, rec.Result().Cookies(), auth.InternalAuthSessionName)
}

func TestCheckSecurityRequirementsReturnsStoreErrorsImmediately(t *testing.T) {
	storeErr := errors.New("store failed")
	store := &errSessionStore{err: storeErr}
	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	rec := httptest.NewRecorder()

	user, err := checkSecurityRequirements(rec, req, authSecurityRequirements("cookie_auth", "oidc_auth"), logging.Dummy(), nil, newMiddlewareAuthService("oidc-user"), store, &auth.OIDCConfig{}, nil)

	require.Nil(t, user)
	require.ErrorIs(t, err, storeErr)
	require.Equal(t, 1, store.calls)
	require.Empty(t, rec.Result().Cookies())
}

func TestCheckSecurityRequirementsRejectsHistoricalOIDCSession(t *testing.T) {
	store := newMiddlewareSessionStore(t)
	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.AddCookie(oidcSessionCookie(t, store, "oidc-user", false))
	rec := httptest.NewRecorder()

	user, err := checkSecurityRequirements(rec, req, authSecurityRequirements("oidc_auth"), logging.Dummy(), nil, newMiddlewareAuthService("oidc-user"), store, &auth.OIDCConfig{}, nil)

	require.Nil(t, user)
	require.ErrorIs(t, err, auth.ErrAuthenticatingRequest)
	requireSessionExpired(t, rec.Result().Cookies(), auth.OIDCAuthSessionName)
}

func TestCheckSecurityRequirementsRejectsExpiredOIDCSession(t *testing.T) {
	store := newMiddlewareSessionStore(t)
	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.AddCookie(oidcSessionCookieWithExpiry(t, store, "oidc-user", time.Now().Add(-time.Second)))
	rec := httptest.NewRecorder()

	user, err := checkSecurityRequirements(rec, req, authSecurityRequirements("oidc_auth"), logging.Dummy(), nil, newMiddlewareAuthService("oidc-user"), store, &auth.OIDCConfig{}, nil)

	require.Nil(t, user)
	require.ErrorIs(t, err, auth.ErrAuthenticatingRequest)
	require.ErrorIs(t, err, auth.ErrSessionExpired)
	requireSessionExpired(t, rec.Result().Cookies(), auth.OIDCAuthSessionName)
}

func authSecurityRequirements(providers ...string) openapi3.SecurityRequirements {
	requirements := make(openapi3.SecurityRequirements, len(providers))
	for i, provider := range providers {
		requirements[i] = openapi3.SecurityRequirement{provider: []string{}}
	}
	return requirements
}

func newMiddlewareSessionStore(t testing.TB) sessions.Store {
	t.Helper()
	store, err := auth.NewSessionStore([]byte("some secret"), auth.SessionStoreOptions{MaxAge: 3600})
	require.NoError(t, err)
	return store
}

func oidcSessionCookie(t testing.TB, store sessions.Store, username string, currentSchema bool) *http.Cookie {
	t.Helper()
	expiresAt := time.Now().Add(time.Hour)
	if !currentSchema {
		expiresAt = time.Time{}
	}
	return oidcSessionCookieWithExpiry(t, store, username, expiresAt)
}

func oidcSessionCookieWithExpiry(t testing.TB, store sessions.Store, username string, expiresAt time.Time) *http.Cookie {
	t.Helper()
	claims := oidcencoding.Claims{
		"iss": "https://issuer.example",
		"sub": username,
	}
	data, err := json.Marshal(claims)
	require.NoError(t, err)
	return sessionCookie(t, store, auth.OIDCAuthSessionName, map[any]any{
		auth.IDTokenClaimsSessionKey: string(data),
	}, func(session *sessions.Session) {
		if !expiresAt.IsZero() {
			auth.MarkOIDCSessionClaimsCurrent(session, expiresAt)
		}
	})
}

func samlSessionCookie(t testing.TB, store sessions.Store, username string) *http.Cookie {
	t.Helper()
	return sessionCookie(t, store, auth.SAMLAuthSessionName, map[any]any{
		auth.SAMLTokenClaimsSessionKey: oidcencoding.Claims{"external_id": username},
	}, nil)
}

func sessionCookie(t testing.TB, store sessions.Store, name string, values map[any]any, configure func(*sessions.Session)) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	session, err := store.New(req, name)
	require.NoError(t, err)
	for key, value := range values {
		session.Values[key] = value
	}
	if configure != nil {
		configure(session)
	}
	require.NoError(t, auth.SaveSession(req, rec, session))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

func requireSessionExpired(t testing.TB, cookies []*http.Cookie, name string) {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			require.Less(t, cookie.MaxAge, 0)
			return
		}
	}
	t.Fatalf("expected expired %q cookie in response", name)
}

func samlCookieAuthConfig() *auth.CookieAuthConfig {
	return &auth.CookieAuthConfig{
		ExternalUserIDClaimName: "external_id",
		AuthSource:              "saml",
	}
}

type middlewareAuthService struct {
	auth.Service
	secretStore       crypt.SecretStore
	usersByExternalID map[string]*model.User
	usersByUsername   map[string]*model.User
}

func newMiddlewareAuthService(usernames ...string) *middlewareAuthService {
	service := &middlewareAuthService{
		secretStore:       crypt.NewSecretStore([]byte("some secret")),
		usersByExternalID: make(map[string]*model.User),
		usersByUsername:   make(map[string]*model.User),
	}
	for _, username := range usernames {
		user := &model.User{
			CreatedAt:  time.Now().UTC(),
			Username:   username,
			ExternalID: &username,
			Source:     "test",
		}
		service.usersByExternalID[username] = user
		service.usersByUsername[username] = user
	}
	return service
}

func (s *middlewareAuthService) SecretStore() crypt.SecretStore {
	return s.secretStore
}

func (s *middlewareAuthService) GetUser(_ context.Context, username string) (*model.User, error) {
	user, ok := s.usersByUsername[username]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return user, nil
}

func (s *middlewareAuthService) GetUserByExternalID(_ context.Context, externalID string) (*model.User, error) {
	user, ok := s.usersByExternalID[externalID]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return user, nil
}

type errSessionStore struct {
	err   error
	calls int
}

func (s *errSessionStore) Get(_ *http.Request, _ string) (*sessions.Session, error) {
	s.calls++
	return nil, s.err
}

func (s *errSessionStore) New(_ *http.Request, name string) (*sessions.Session, error) {
	return sessions.NewSession(s, name), nil
}

func (s *errSessionStore) Save(_ *http.Request, _ http.ResponseWriter, _ *sessions.Session) error {
	return nil
}
