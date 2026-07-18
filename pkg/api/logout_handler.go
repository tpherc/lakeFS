package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

// NewLogoutHandler returns a handler to clear the user sessions and redirect the user to the login page.
func NewLogoutHandler(sessionStore sessions.Store, logger logging.Logger, authConfig *config.BaseAuth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, sessionName := range []string{auth.InternalAuthSessionName, auth.OIDCAuthSessionName, auth.SAMLAuthSessionName} {
			if err := auth.ClearSession(w, r, sessionStore, sessionName); err != nil {
				logger.WithError(err).WithField("session", sessionName).Error("Failed to clear session during logout")
				writeError(w, r, http.StatusInternalServerError, err)
				return
			}
		}
		logoutRedirectURL, err := resolveLogoutRedirectURL(authConfig)
		if err != nil {
			logger.WithError(err).Error("Failed to resolve logout redirect URL")
			writeError(w, r, http.StatusInternalServerError, err)
			return
		}
		http.Redirect(w, r, logoutRedirectURL, http.StatusTemporaryRedirect)
	}
}

func resolveLogoutRedirectURL(authConfig *config.BaseAuth) (string, error) {
	if authConfig == nil {
		return "", fmt.Errorf("missing auth config")
	}
	logoutRedirectURL := authConfig.LogoutRedirectURL
	oidcProvider := authConfig.Providers.OIDC
	if oidcProvider == nil ||
		!oidcProvider.IsConfigured() ||
		(len(oidcProvider.LogoutEndpointQueryParameters) == 0 && oidcProvider.LogoutClientIDQueryParameter == "") {
		return logoutRedirectURL, nil
	}
	return oidcLogoutRedirectURL(logoutRedirectURL, oidcProvider)
}

func oidcLogoutRedirectURL(logoutRedirectURL string, oidcProvider *config.OIDCProvider) (string, error) {
	redirectURL, err := url.Parse(logoutRedirectURL)
	if err != nil {
		return "", fmt.Errorf("parse logout redirect URL: %w", err)
	}
	query := redirectURL.Query()

	params := oidcProvider.LogoutEndpointQueryParameters
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
	if key := strings.TrimSpace(oidcProvider.LogoutClientIDQueryParameter); key != "" {
		query.Set(key, oidcProvider.ClientID)
	}

	redirectURL.RawQuery = query.Encode()
	return redirectURL.String(), nil
}
