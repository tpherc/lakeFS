package authentication

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/treeverse/lakefs/pkg/config"
)

type oidcLogoutRedirect struct {
	endSessionEndpoint            string
	clientID                      string
	logoutEndpointQueryParameters []string
	logoutClientIDQueryParameter  string
}

func newOIDCLogoutRedirect(providerConfig config.OIDCProvider, endSessionEndpoint string) oidcLogoutRedirect {
	params := append([]string(nil), providerConfig.LogoutEndpointQueryParameters...)
	return oidcLogoutRedirect{
		endSessionEndpoint:            endSessionEndpoint,
		clientID:                      providerConfig.ClientID,
		logoutEndpointQueryParameters: params,
		logoutClientIDQueryParameter:  providerConfig.LogoutClientIDQueryParameter,
	}
}

func (r oidcLogoutRedirect) URL(fallbackURL string) (string, error) {
	logoutURL := fallbackURL
	if r.endSessionEndpoint != "" {
		logoutURL = r.endSessionEndpoint
	}
	redirectURL, err := url.Parse(logoutURL)
	if err != nil {
		return "", fmt.Errorf("parse logout redirect URL: %w", err)
	}
	query := redirectURL.Query()

	params := r.logoutEndpointQueryParameters
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
	if key := strings.TrimSpace(r.logoutClientIDQueryParameter); key != "" {
		query.Set(key, r.clientID)
	}

	redirectURL.RawQuery = query.Encode()
	return redirectURL.String(), nil
}
