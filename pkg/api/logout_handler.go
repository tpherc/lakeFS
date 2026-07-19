package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/logging"
)

// NewLogoutHandler returns a handler to clear the user sessions and redirect the user to the login page.
func NewLogoutHandler(sessionStore sessions.Store, logger logging.Logger, logoutRedirectURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := clearLogoutSessions(w, r, sessionStore, logger); err != nil {
			writeError(w, r, http.StatusInternalServerError, err)
			return
		}
		http.Redirect(w, r, logoutRedirectURL, http.StatusTemporaryRedirect)
	}
}

func clearLogoutSessions(w http.ResponseWriter, r *http.Request, sessionStore sessions.Store, logger logging.Logger) error {
	// Logout succeeds only when all lakeFS-owned auth sessions are cleared.
	// Keep attempting every clear so one failure does not mask others.
	var errs []error
	for _, sessionName := range []string{auth.InternalAuthSessionName, auth.OIDCAuthSessionName, auth.SAMLAuthSessionName} {
		if err := auth.ClearSession(w, r, sessionStore, sessionName); err != nil {
			logger.WithError(err).WithField("session", sessionName).Error("Failed to clear session during logout")
			errs = append(errs, fmt.Errorf("%s: %w", sessionName, err))
		}
	}
	return errors.Join(errs...)
}
