package authentication

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestCAPOIDCClientExchangesVerifiedCode(t *testing.T) {
	const (
		clientID     = "lakefs"
		clientSecret = "secret"
		callbackBase = "http://127.0.0.1:8000"
		callbackURL  = callbackBase + "/api/v1/oidc/callback"
	)
	testProvider := capoidc.StartTestProvider(t, capoidc.WithNoTLS())
	testProvider.SetClientCreds(clientID, clientSecret)
	testProvider.SetSupportedScopes("openid", "profile")
	testProvider.SetAllowedRedirectURIs([]string{callbackURL})
	signingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	testProvider.SetSigningKeys(signingKey, &signingKey.PublicKey, capoidc.RS256, "lakefs-test-rs256")
	testProvider.SetSubjectInfo(map[string]*capoidc.TestSubject{
		"alice@example.com": {Password: "password"},
	})

	client, err := newCAPOIDCClient(context.Background(), config.OIDCProvider{
		URL:             testProvider.Addr(),
		ClientID:        clientID,
		ClientSecret:    config.SecureString(clientSecret),
		CallbackBaseURL: callbackBase,
		AuthorizeEndpointQueryParameters: map[string]string{
			"kc_idp_hint": "keycloak",
			"max_age":     "0",
		},
	})
	require.NoError(t, err)
	t.Cleanup(client.Close)

	transaction, authURL, err := client.BeginLogin(context.Background(), oidcBeginLoginInput{
		CallbackURL: callbackURL,
		Next:        "/repositories",
	})
	require.NoError(t, err)
	require.NotEmpty(t, transaction.StateValue)
	require.NotEmpty(t, transaction.NonceValue)
	require.NotEmpty(t, transaction.CodeVerifier)
	require.NotNil(t, transaction.MaxAge)
	require.Equal(t, uint(0), *transaction.MaxAge)

	parsedAuthURL, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, "S256", parsedAuthURL.Query().Get("code_challenge_method"))
	require.Equal(t, "keycloak", parsedAuthURL.Query().Get("kc_idp_hint"))
	require.Equal(t, "0", parsedAuthURL.Query().Get("max_age"))

	verifier, err := capoidc.NewCodeVerifier(capoidc.WithVerifier(transaction.CodeVerifier))
	require.NoError(t, err)
	testProvider.SetExpectedState(transaction.StateValue)
	testProvider.SetExpectedAuthNonce(transaction.NonceValue)
	testProvider.SetPKCEVerifier(verifier)

	httpClient := *testProvider.HTTPClient()
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	authResp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Equal(t, http.StatusOK, authResp.StatusCode)
	body, err := io.ReadAll(authResp.Body)
	require.NoError(t, err)

	loginResp, err := httpClient.PostForm(testProvider.Addr()+"/login", url.Values{
		"uname":        {"alice@example.com"},
		"psw":          {"password"},
		"state":        {hiddenInputValue(t, string(body), "state")},
		"code":         {hiddenInputValue(t, string(body), "code")},
		"redirect_uri": {hiddenInputValue(t, string(body), "redirect_uri")},
	})
	require.NoError(t, err)
	defer loginResp.Body.Close()
	_, _ = io.Copy(io.Discard, loginResp.Body)
	require.Equal(t, http.StatusFound, loginResp.StatusCode)
	callbackLocation, err := loginResp.Location()
	require.NoError(t, err)
	require.Equal(t, callbackURL, callbackLocation.Scheme+"://"+callbackLocation.Host+callbackLocation.Path)

	claims, err := client.Exchange(context.Background(), transaction, oidcCallbackInput{
		State: callbackLocation.Query().Get("state"),
		Code:  callbackLocation.Query().Get("code"),
	})
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", claims["sub"])
}

func TestSupportedOIDCSigningAlgs(t *testing.T) {
	require.Equal(t, []capoidc.Alg{
		capoidc.RS256,
		capoidc.PS256,
		capoidc.ES256,
		capoidc.RS384,
		capoidc.PS384,
		capoidc.ES384,
	}, supportedOIDCSigningAlgs())
}

func hiddenInputValue(t *testing.T, body, name string) string {
	t.Helper()
	prefix := `name="` + name + `" type="hidden" value="`
	start := strings.Index(body, prefix)
	require.NotEqual(t, -1, start)
	valueStart := start + len(prefix)
	valueEnd := strings.Index(body[valueStart:], `"`)
	require.NotEqual(t, -1, valueEnd)
	return body[valueStart : valueStart+valueEnd]
}
