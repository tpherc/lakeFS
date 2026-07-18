package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestOIDCSessionReissueOnlyWhenEncodingUpgradeNeeded(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	store, err := auth.NewSessionStore(secret, auth.SessionStoreOptions{MaxAge: 3600})
	if err != nil {
		t.Fatal(err)
	}
	externalID := "oidc-user"
	authService := oidcMiddlewareAuthService{
		user: &model.User{
			Username:   externalID,
			ExternalID: &externalID,
			Source:     "oidc",
		},
	}
	securityRequirements := openapi3.SecurityRequirements{
		{"oidc_auth": []string{}},
	}

	t.Run("legacy valid cookie reissues once", func(t *testing.T) {
		legacyStore := sessions.NewCookieStore(secret)
		req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		rec := httptest.NewRecorder()
		session, err := legacyStore.Get(req, auth.OIDCAuthSessionName)
		if err != nil {
			t.Fatal(err)
		}
		session.Values[auth.IDTokenClaimsSessionKey] = `{"sub":"oidc-user"}`
		if err := session.Save(req, rec); err != nil {
			t.Fatal(err)
		}

		gotReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		gotReq.AddCookie(responseCookieByName(t, rec.Result(), auth.OIDCAuthSessionName))
		gotRec := httptest.NewRecorder()

		user, err := checkSecurityRequirements(gotRec, gotReq, securityRequirements, logging.ContextUnavailable(), nil, authService, store, &auth.OIDCConfig{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if user == nil || user.Username != externalID {
			t.Fatalf("unexpected user: %#v", user)
		}
		if responseCookieByName(t, gotRec.Result(), auth.OIDCAuthSessionName) == nil {
			t.Fatal("expected legacy OIDC cookie to be reissued")
		}
	})

	t.Run("current cookie does not reissue", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		rec := httptest.NewRecorder()
		session, err := store.Get(req, auth.OIDCAuthSessionName)
		if err != nil {
			t.Fatal(err)
		}
		session.Values[auth.IDTokenClaimsSessionKey] = `{"sub":"oidc-user"}`
		if err := auth.SaveSession(req, rec, session); err != nil {
			t.Fatal(err)
		}

		gotReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/repositories", nil)
		gotReq.AddCookie(responseCookieByName(t, rec.Result(), auth.OIDCAuthSessionName))
		gotRec := httptest.NewRecorder()

		user, err := checkSecurityRequirements(gotRec, gotReq, securityRequirements, logging.ContextUnavailable(), nil, authService, store, &auth.OIDCConfig{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if user == nil || user.Username != externalID {
			t.Fatalf("unexpected user: %#v", user)
		}
		if cookie := responseCookieByName(t, gotRec.Result(), auth.OIDCAuthSessionName); cookie != nil {
			t.Fatalf("expected current OIDC cookie not to be reissued, got %q", cookie.String())
		}
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
