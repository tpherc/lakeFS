package authentication

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestOIDCCallbackResolverUsesFixedCallbackBaseURL(t *testing.T) {
	resolver, err := newOIDCCallbackResolver(config.OIDCProvider{
		CallbackBaseURL: "https://lakefs.example/",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://evil.example/oidc/login", nil)
	got, err := resolver.RedirectURI(req)
	require.NoError(t, err)
	require.Equal(t, "https://lakefs.example/api/v1/oidc/callback", got)
}

func TestOIDCCallbackResolverRequiresExactAllowedRequestBaseURL(t *testing.T) {
	resolver, err := newOIDCCallbackResolver(config.OIDCProvider{
		CallbackBaseURLs: []string{"https://lakefs.example", "https://alt.example"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/oidc/login", nil)
	req.Header.Set("X-Forwarded-Host", "alt.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	got, err := resolver.RedirectURI(req)
	require.NoError(t, err)
	require.Equal(t, "https://lakefs.example/api/v1/oidc/callback", got)

	req = httptest.NewRequest(http.MethodGet, "https://evil.example/oidc/login", nil)
	_, err = resolver.RedirectURI(req)
	require.Error(t, err)
}

func TestOIDCProviderConfigRejectsLoopbackLookalikes(t *testing.T) {
	for _, callbackBaseURL := range []string{
		"http://localhost.example.com",
		"http://127.0.0.1.example.com",
		"http://10.0.0.1",
	} {
		t.Run(callbackBaseURL, func(t *testing.T) {
			cfg := validOIDCProviderConfig()
			cfg.CallbackBaseURL = callbackBaseURL
			require.Error(t, cfg.Validate())
		})
	}
}

func validOIDCProviderConfig() config.OIDCProvider {
	return config.OIDCProvider{
		URL:             "https://idp.example",
		ClientID:        "lakefs",
		ClientSecret:    config.SecureString("secret"),
		CallbackBaseURL: "https://lakefs.example",
	}
}
