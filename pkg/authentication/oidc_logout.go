package authentication

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/treeverse/lakefs/pkg/config"
)

func compileOIDCLogoutURL(rawLogoutURL string, providerConfig config.OIDCProvider) (string, error) {
	logoutURL := strings.TrimSpace(rawLogoutURL)
	if logoutURL == "" {
		return "", fmt.Errorf("auth.logout_redirect_url is required for OIDC logout")
	}
	redirectURL, err := url.Parse(logoutURL)
	if err != nil {
		return "", fmt.Errorf("parse logout redirect URL: %w", err)
	}
	if redirectURL.IsAbs() {
		if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
			return "", fmt.Errorf("auth.logout_redirect_url must use http or https")
		}
		if redirectURL.Host == "" {
			return "", fmt.Errorf("auth.logout_redirect_url must include a host")
		}
	} else if !strings.HasPrefix(logoutURL, "/") || strings.HasPrefix(logoutURL, "//") {
		return "", fmt.Errorf("auth.logout_redirect_url must be an absolute URL or root-relative path")
	}
	query := redirectURL.Query()

	params := providerConfig.LogoutEndpointQueryParameters
	if len(params)%2 != 0 {
		return "", fmt.Errorf("auth.providers.oidc.logout_endpoint_query_parameters must contain key/value pairs")
	}
	for i := 0; i < len(params); i += 2 {
		key := strings.TrimSpace(params[i])
		if key == "" {
			return "", fmt.Errorf("auth.providers.oidc.logout_endpoint_query_parameters contains an empty key")
		}
		query.Set(key, params[i+1])
	}
	if key := strings.TrimSpace(providerConfig.LogoutClientIDQueryParameter); key != "" {
		query.Set(key, providerConfig.ClientID)
	}

	redirectURL.RawQuery = query.Encode()
	return redirectURL.String(), nil
}
