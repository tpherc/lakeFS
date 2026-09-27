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

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestOIDCCallbackPrincipalTagsAtomicSession(t *testing.T) {
	const departmentClaim = "https://aws.amazon.com/tags/principal_tags/Department"
	store := testSessionStore(t)
	callbackReq := oidcCallbackRequest(t, store)
	client := &fakeOIDCClient{exchangeFunc: func(_ context.Context, _ *oidcTransaction, _ oidcCallbackInput) (encoding.Claims, error) {
		return encoding.Claims{"iss": "https://idp.example", "sub": "alice", departmentClaim: "Engineering"}, nil
	}}
	authService := newOIDCCallbackAuthService()
	cfg := config.OIDC{ValidateIDTokenClaims: map[string]string{departmentClaim: "Engineering"}}
	service := testOIDCServiceWithAuth(t, client, cfg, authService)
	rec := httptest.NewRecorder()
	service.OauthCallback(rec, callbackReq, store)
	require.Equal(t, "/repositories", rec.Header().Get("Location"))
	require.Len(t, authService.createdUsers, 1)

	authenticatedCookies := 0
	for _, cookie := range rec.Result().Cookies() {
		loadReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/repositories", nil)
		loadReq.AddCookie(cookie)
		session, err := store.Get(loadReq, auth.OIDCAuthSessionName)
		require.NoError(t, err)
		claimsJSON, ok := session.Values[auth.IDTokenClaimsSessionKey].(string)
		if !ok {
			continue // The earlier cookie only consumes the login transaction.
		}
		authenticatedCookies++
		require.Len(t, session.Values, 4, "claims plus schema, expiry, and encoding metadata only")
		require.Equal(t, 3, session.Values["_lakefs_oidc_claims_schema_version"])
		require.NotContains(t, session.Values, oidcTransactionSessionKey)
		var claims encoding.Claims
		require.NoError(t, json.Unmarshal([]byte(claimsJSON), &claims))
		require.Equal(t, "Engineering", claims[departmentClaim])
		require.Contains(t, claims, principaltags.NamespaceClaim)
		require.NoError(t, auth.ValidateOIDCRequiredClaims(claims, cfg.ValidateIDTokenClaims))
		result, err := auth.AuthenticateOIDCSession(t.Context(), logging.Dummy(), service.provisioner, session, (*auth.OIDCConfig)(&cfg))
		require.NoError(t, err)
		require.Equal(t, principaltags.Tags{"Department": "Engineering"}, result.PrincipalTags)
		require.Equal(t, authService.createdUsers[0].Username, result.User.Username)
	}
	require.Equal(t, 1, authenticatedCookies)
}

func TestOIDCCallbackRejectsInvalidPrincipalTagsBeforeProvisioning(t *testing.T) {
	oversizedTags := principaltags.Tags{}
	for _, key := range []string{"A", "B", "C", "D", "E", "F", "G", "H"} {
		oversizedTags[key] = strings.Repeat("x", 256)
	}
	for _, test := range []struct {
		name          string
		claims        encoding.Claims
		exchangeError error
	}{
		{name: "malformed namespace", claims: encoding.Claims{principaltags.NamespaceClaim: "invalid"}},
		{name: "valid tags exceed normalized claims budget", claims: encoding.Claims{principaltags.NamespaceClaim: principaltags.ToNestedClaim(oversizedTags)}},
		{name: "multiple nested values", claims: encoding.Claims{
			principaltags.NamespaceClaim: map[string]any{"principal_tags": map[string]any{"Department": []any{"A", "B"}}},
		}},
		{name: "invalid flattened value", claims: encoding.Claims{
			"https://aws.amazon.com/tags/principal_tags/Department": []any{"Engineering"},
		}},
		{name: "unverified exchange result", claims: encoding.Claims{
			principaltags.NamespaceClaim: principaltags.ToNestedClaim(principaltags.Tags{"Department": "Engineering"}),
		}, exchangeError: errors.New("token verification failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := testSessionStore(t)
			callbackReq := oidcCallbackRequest(t, store)
			claims := test.claims
			claims["iss"] = "https://idp.example"
			claims["sub"] = "alice"
			client := &fakeOIDCClient{exchangeFunc: func(_ context.Context, _ *oidcTransaction, _ oidcCallbackInput) (encoding.Claims, error) {
				return claims, test.exchangeError
			}}
			authService := newOIDCCallbackAuthService()
			service := testOIDCServiceWithAuth(t, client, config.OIDC{}, authService)
			rec := httptest.NewRecorder()
			service.OauthCallback(rec, callbackReq, store)
			require.Equal(t, "/auth/login", rec.Header().Get("Location"))
			require.Empty(t, authService.createdUsers)
			require.Empty(t, authService.addedGroups)
			require.Empty(t, authService.friendlyNameUpdates)
			assertNoAuthenticatedOIDCCookies(t, store, rec)
		})
	}
}

func TestNormalizeOIDCPrincipalTagsCanonicalNamespaceWins(t *testing.T) {
	claims := encoding.Claims{
		"iss": "https://idp.example", "sub": "alice",
		principaltags.NamespaceClaim: map[string]any{
			"principal_tags":      map[string]any{"Department": []any{"Engineering"}},
			"transitive_tag_keys": []any{"Department"},
		},
	}
	normalized, err := normalizeOIDCClaims(claims, config.OIDC{FriendlyNameClaimName: principaltags.NamespaceClaim})
	require.NoError(t, err)
	require.Equal(t, principaltags.ToNestedClaim(principaltags.Tags{"Department": "Engineering"}), normalized[principaltags.NamespaceClaim])
	claims[principaltags.NamespaceClaim] = map[string]any{"transitive_tag_keys": []any{"Department"}}
	normalized, err = normalizeOIDCClaims(claims, config.OIDC{FriendlyNameClaimName: principaltags.NamespaceClaim})
	require.NoError(t, err)
	require.NotContains(t, normalized, principaltags.NamespaceClaim, "transitive metadata is not retained for a tagless session")
}

func TestOIDCCallbackEncryptedCookieOverflowBeforeProvisioning(t *testing.T) {
	for _, existingUser := range []bool{false, true} {
		t.Run(map[bool]string{false: "new user", true: "existing user"}[existingUser], func(t *testing.T) {
			store := testSessionStore(t)
			claims := encoding.Claims{"iss": "https://idp.example", "sub": "alice", "name": ""}
			data, err := json.Marshal(claims)
			require.NoError(t, err)
			claims["name"] = strings.Repeat("a", oidcClaimsMaxJSONSize-len(data))
			cfg := config.OIDC{FriendlyNameClaimName: "name", PersistFriendlyName: true}
			claimsJSON, err := prepareOIDCSessionClaims(claims, cfg)
			require.NoError(t, err)
			require.Len(t, claimsJSON, oidcClaimsMaxJSONSize)
			callbackReq := oidcCallbackRequest(t, store)
			client := &fakeOIDCClient{exchangeFunc: func(_ context.Context, _ *oidcTransaction, _ oidcCallbackInput) (encoding.Claims, error) {
				return claims, nil
			}}
			authService := newOIDCCallbackAuthService()
			if existingUser {
				externalID := oidcExternalIDForTest("https://idp.example", "alice")
				authService = newOIDCCallbackAuthService(&model.User{Username: "alice", ExternalID: &externalID, Source: "oidc"})
			}
			service := testOIDCServiceWithAuth(t, client, cfg, authService)
			rec := httptest.NewRecorder()
			service.OauthCallback(rec, callbackReq, store)
			require.Equal(t, "/auth/login", rec.Header().Get("Location"))
			require.Empty(t, authService.createdUsers)
			require.Empty(t, authService.friendlyNameUpdates)
			assertNoAuthenticatedOIDCCookies(t, store, rec)
		})
	}
}

func TestOIDCCookiePreflightMatchesSaveBoundary(t *testing.T) {
	store := testSessionStore(t)
	expiresAt := time.Now().Add(time.Hour)
	for _, size := range []int{300, 1900, 2000, 2048} {
		claims := encoding.Claims{
			"iss": "https://idp.example", "sub": "alice", "name": "",
			principaltags.NamespaceClaim: principaltags.ToNestedClaim(principaltags.Tags{"pol": "NATO", "clr": "S", "nat": "AU"}),
		}
		data, err := json.Marshal(claims)
		require.NoError(t, err)
		claims["name"] = strings.Repeat("a", size-len(data))
		claimsJSON, err := prepareOIDCSessionClaims(claims, config.OIDC{FriendlyNameClaimName: "name"})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/callback", nil)
		rec := httptest.NewRecorder()
		session, err := (oidcSessionStore{store: store}).Load(rec, req)
		require.NoError(t, err)
		session.session.Values[oidcTransactionSessionKey] = strings.Repeat("t", 1000)
		preflightErr := session.PreflightClaimsJSON(claimsJSON, expiresAt)
		require.Empty(t, rec.Header().Values("Set-Cookie"))
		require.NotContains(t, session.session.Values, auth.IDTokenClaimsSessionKey)
		require.Contains(t, session.session.Values, oidcTransactionSessionKey)
		saveErr := session.SaveClaimsJSON(claimsJSON, expiresAt)
		if preflightErr != nil {
			require.Error(t, saveErr)
			require.Empty(t, rec.Result().Cookies())
			require.NotContains(t, session.session.Values, auth.IDTokenClaimsSessionKey, "failed save must not mutate the session")
			candidate, err := session.prepareClaimsSession(claimsJSON, expiresAt)
			require.NoError(t, err)
			unbounded := testSessionStore(t)
			unbounded.Codecs[0].(*securecookie.SecureCookie).MaxLength(0)
			encoded, err := unbounded.Codecs[0].Encode(candidate.Name(), candidate.Values)
			require.NoError(t, err)
			require.Greater(t, len(encoded), 4096)
		} else {
			require.NoError(t, saveErr)
			cookies := rec.Result().Cookies()
			require.Len(t, cookies, 1)
			require.LessOrEqual(t, len(cookies[0].Value), 4096)
			require.NotContains(t, session.session.Values, oidcTransactionSessionKey)
		}
	}
}

func oidcCallbackRequest(t *testing.T, store *sessions.CookieStore) *http.Request {
	t.Helper()
	loginReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	loginRec := httptest.NewRecorder()
	transaction := sampleOIDCTransaction("https://lakefs.example/api/v1/oidc/callback", "/repositories")
	require.NoError(t, (oidcSessionStore{store: store}).SaveTransaction(loginRec, loginReq, transaction))
	callbackReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example/api/v1/oidc/callback?state=state-1&code=code-1", nil)
	for _, cookie := range loginRec.Result().Cookies() {
		callbackReq.AddCookie(cookie)
	}
	return callbackReq
}

func assertNoAuthenticatedOIDCCookies(t *testing.T, store *sessions.CookieStore, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/repositories", nil)
		req.AddCookie(cookie)
		session, err := store.Get(req, auth.OIDCAuthSessionName)
		require.NoError(t, err)
		require.NotContains(t, session.Values, auth.IDTokenClaimsSessionKey)
	}
}
