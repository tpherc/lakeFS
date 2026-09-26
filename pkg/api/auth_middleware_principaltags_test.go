package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	oidcencoding "github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestAuthenticationMiddlewarePrincipalTags(t *testing.T) {
	for _, generic := range []bool{false, true} {
		name := "API"
		if generic {
			name = "generic"
		}
		t.Run(name, func(t *testing.T) {
			for _, provider := range []string{"tagged OIDC", "tagless OIDC", "malformed OIDC", "basic", "JWT", "internal cookie", "SAML"} {
				t.Run(provider, func(t *testing.T) {
					store := newMiddlewareSessionStore(t)
					service := newOIDCMiddlewareAuthService("principal")
					service.usersByExternalID["principal"] = service.usersByUsername["principal"]
					req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
					req = req.WithContext(auth.WithPrincipalTags(req.Context(), principaltags.Tags{"inherited": "must disappear"}))
					var expected principaltags.Tags
					switch provider {
					case "tagged OIDC", "tagless OIDC", "malformed OIDC":
						claims := oidcencoding.Claims{"iss": "https://issuer.example", "sub": "principal"}
						if provider == "tagged OIDC" {
							expected = principaltags.Tags{"clr": "S", "Project": "Automation"}
							claims[principaltags.NamespaceClaim] = principaltags.ToNestedClaim(expected)
						}
						if provider == "malformed OIDC" {
							claims[principaltags.NamespaceClaim] = map[string]any{"principal_tags": map[string]any{"clr": "S"}}
						}
						data, err := json.Marshal(claims)
						require.NoError(t, err)
						req.AddCookie(sessionCookie(t, store, auth.OIDCAuthSessionName, map[any]any{auth.IDTokenClaimsSessionKey: string(data)}, func(s *sessions.Session) { auth.MarkOIDCSessionClaimsCurrent(s, time.Now().Add(time.Hour)) }))
					case "basic":
						req.SetBasicAuth("access-key", "secret")
					case "JWT", "internal cookie":
						token, err := auth.GenerateJWTLogin(service.SecretStore().SharedSecret(), "principal", time.Now(), time.Now().Add(time.Hour))
						require.NoError(t, err)
						if provider == "JWT" {
							req.Header.Set("Authorization", "Bearer "+token)
						} else {
							req.AddCookie(sessionCookie(t, store, auth.InternalAuthSessionName, map[any]any{auth.TokenSessionKeyName: token}, nil))
						}
					case "SAML":
						req.AddCookie(samlSessionCookie(t, store, "principal"))
					}
					called := false
					next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						called = true
						user, err := auth.GetUser(r.Context())
						require.NoError(t, err)
						require.Equal(t, "principal", user.Username)
						tags, found := auth.PrincipalTagsFromContext(r.Context())
						require.True(t, found, "even a tagless principal needs an explicit snapshot")
						require.Equal(t, expected, tags)
						w.WriteHeader(http.StatusNoContent)
					})
					provisioner := newMiddlewareProvisioner(t, service)
					var middleware func(http.Handler) http.Handler
					if generic {
						var err error
						middleware, err = GenericAuthMiddleware(logging.Dummy(), principalTestAuthenticator{}, service, provisioner, &auth.OIDCConfig{}, samlCookieAuthConfig(), false)
						require.NoError(t, err)
					} else {
						swagger, err := apigen.GetSwagger()
						require.NoError(t, err)
						middleware = AuthMiddleware(logging.Dummy(), swagger, principalTestAuthenticator{}, service, provisioner, store, &auth.OIDCConfig{}, samlCookieAuthConfig())
					}
					rec := httptest.NewRecorder()
					middleware(next).ServeHTTP(rec, req)
					if provider == "malformed OIDC" {
						require.False(t, called)
						require.Equal(t, http.StatusUnauthorized, rec.Code)
						requireSessionExpired(t, rec.Result().Cookies(), auth.OIDCAuthSessionName)
					} else {
						require.True(t, called)
						require.Equal(t, http.StatusNoContent, rec.Code)
					}
				})
			}
		})
	}
}

type principalTestAuthenticator struct{}

func (principalTestAuthenticator) AuthenticateUser(_ context.Context, accessKey, secret string) (string, error) {
	if accessKey != "access-key" || secret != "secret" {
		return "", auth.ErrAuthenticatingRequest
	}
	return "principal", nil
}
