package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/authentication"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestNewLoginConfigDoesNotUseOIDCAsImplicitLoginURL(t *testing.T) {
	authConfig := &config.Auth{}
	authConfig.Providers.OIDC = validLoginConfigOIDCProvider()

	loginConfig := newLoginConfig(authConfig)

	require.Empty(t, loginConfig.LoginUrl)
	require.NotNil(t, loginConfig.LoginUrlMethod)
	require.Equal(t, "none", *loginConfig.LoginUrlMethod)
	require.False(t, slices.Contains(loginConfig.LoginCookieNames, auth.OIDCAuthSessionName))
	require.Nil(t, loginConfig.FallbackLoginUrl)
}

func TestNewLoginConfigExplicitOIDCLoginURLDefaultsToRedirect(t *testing.T) {
	authConfig := &config.Auth{}
	authConfig.LoginURL = authentication.OIDCLoginPath
	authConfig.Providers.OIDC = validLoginConfigOIDCProvider()

	loginConfig := newLoginConfig(authConfig)

	require.Equal(t, authentication.OIDCLoginPath, loginConfig.LoginUrl)
	require.NotNil(t, loginConfig.LoginUrlMethod)
	require.Equal(t, config.AuthLoginURLMethodRedirect, *loginConfig.LoginUrlMethod)
}

func TestNewLoginConfigPreservesExplicitLoginURL(t *testing.T) {
	authConfig := &config.Auth{}
	authConfig.LoginURL = "/custom/sso/login"
	authConfig.LoginURLMethod = config.AuthLoginURLMethodSelect
	authConfig.Providers.OIDC = validLoginConfigOIDCProvider()

	loginConfig := newLoginConfig(authConfig)

	require.Equal(t, "/custom/sso/login", loginConfig.LoginUrl)
	require.NotNil(t, loginConfig.LoginUrlMethod)
	require.Equal(t, config.AuthLoginURLMethodSelect, *loginConfig.LoginUrlMethod)
}

func TestNewLoginConfigDoesNotAdvertiseOIDCWhenAuthenticationAPISelected(t *testing.T) {
	authConfig := &config.Auth{}
	authConfig.AuthenticationAPI.Endpoint = "https://auth.example.com"
	authConfig.Providers.OIDC = validLoginConfigOIDCProvider()

	loginConfig := newLoginConfig(authConfig)

	require.NotEqual(t, authentication.OIDCLoginPath, loginConfig.LoginUrl)
	require.False(t, slices.Contains(loginConfig.LoginCookieNames, auth.OIDCAuthSessionName))
}

func TestGetSetupStateTreatsInternalRBACWithLocalRBACFalseAsExternal(t *testing.T) {
	cfg := &config.ConfigImpl{}
	cfg.Features.LocalRBAC = false
	cfg.Auth.RBAC = config.AuthRBACInternal
	controller := &Controller{Config: cfg}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/setup_lakefs", nil)
	controller.GetSetupState(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var response apigen.SetupState
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	require.Equal(t, string(auth.SetupStateInitialized), *response.State)
	require.NotNil(t, response.CommPrefsMissing)
	require.False(t, *response.CommPrefsMissing)
}

func validLoginConfigOIDCProvider() *config.OIDCProvider {
	return &config.OIDCProvider{
		URL:             "https://idp.example",
		ClientID:        "lakefs",
		ClientSecret:    config.SecureString("secret"),
		CallbackBaseURL: "https://lakefs.example",
	}
}
