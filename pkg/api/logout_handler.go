package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

type logoutRedirectResolver interface {
	LogoutRedirectURL(ctx context.Context, fallbackURL string) (string, error)
}

// NewLogoutHandler returns a handler to clear the user sessions and redirect the user to the login page.
func NewLogoutHandler(sessionStore sessions.Store, logger logging.Logger, authConfig *config.BaseAuth, redirectResolver logoutRedirectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cleared, clearErr := clearLogoutSessions(w, r, sessionStore, logger)
		if clearErr != nil && cleared == 0 {
			writeError(w, r, http.StatusInternalServerError, clearErr)
			return
		}
		logoutRedirectURL, err := resolveLogoutRedirectURL(r.Context(), authConfig, redirectResolver)
		if err != nil {
			logger.WithError(err).Error("Failed to resolve logout redirect URL")
			writeError(w, r, http.StatusInternalServerError, err)
			return
		}
		http.Redirect(w, r, logoutRedirectURL, http.StatusTemporaryRedirect)
	}
}

func clearLogoutSessions(w http.ResponseWriter, r *http.Request, sessionStore sessions.Store, logger logging.Logger) (int, error) {
	var errs []error
	cleared := 0
	for _, sessionName := range []string{auth.InternalAuthSessionName, auth.OIDCAuthSessionName, auth.SAMLAuthSessionName} {
		if err := auth.ClearSession(w, r, sessionStore, sessionName); err != nil {
			logger.WithError(err).WithField("session", sessionName).Error("Failed to clear session during logout")
			errs = append(errs, fmt.Errorf("%s: %w", sessionName, err))
			continue
		}
		cleared++
	}
	return cleared, errors.Join(errs...)
}

func resolveLogoutRedirectURL(ctx context.Context, authConfig *config.BaseAuth, redirectResolver logoutRedirectResolver) (string, error) {
	if authConfig == nil {
		return "", fmt.Errorf("missing auth config")
	}
	logoutRedirectURL := authConfig.LogoutRedirectURL
	if redirectResolver == nil {
		return logoutRedirectURL, nil
	}
	return redirectResolver.LogoutRedirectURL(ctx, logoutRedirectURL)
}
