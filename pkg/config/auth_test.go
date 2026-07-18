package config

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthValidateRejectsAuthenticationAPIWithOIDCProvider(t *testing.T) {
	authConfig := &Auth{}
	authConfig.AuthenticationAPI.Endpoint = "https://auth.example.com"
	authConfig.Providers.OIDC = &OIDCProvider{
		URL:             "https://issuer.example.com",
		ClientID:        "client",
		ClientSecret:    SecureString("secret"),
		CallbackBaseURL: "https://lakefs.example.com",
	}

	err := authConfig.Validate()

	require.Error(t, err)
	require.True(t, errors.Is(err, ErrBadConfiguration))
	require.Contains(t, err.Error(), "auth.authentication_api and auth.providers.oidc are mutually exclusive")
}
