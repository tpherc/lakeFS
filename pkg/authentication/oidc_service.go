package authentication

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/authentication/apiclient"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/httputil"
	"github.com/treeverse/lakefs/pkg/logging"
)

const (
	OIDCLoginPath = "/oidc/login"

	oidcDefaultPostLoginTarget = "/"
)

type OIDCService struct {
	oidc                 oidcProtocolClient
	callbacks            oidcCallbackResolver
	userClaimsConfig     config.OIDC
	postLoginRedirectURL string
	logger               logging.Logger
}

func NewOIDCService(ctx context.Context, providerConfig config.OIDCProvider, userClaimsConfig config.OIDC, logger logging.Logger) (*OIDCService, error) {
	oidcClient, err := newCAPOIDCClient(ctx, providerConfig)
	if err != nil {
		return nil, err
	}
	callbacks, err := newOIDCCallbackResolver(providerConfig)
	if err != nil {
		oidcClient.Close()
		return nil, err
	}
	return &OIDCService{
		oidc:                 oidcClient,
		callbacks:            callbacks,
		userClaimsConfig:     userClaimsConfig,
		postLoginRedirectURL: providerConfig.PostLoginRedirectURL,
		logger:               logger.WithField("service", "oidc_authentication"),
	}, nil
}

func (s *OIDCService) IsExternalPrincipalsEnabled() bool {
	return false
}

func (s *OIDCService) Shutdown(_ context.Context) error {
	s.oidc.Close()
	return nil
}

func (s *OIDCService) ExternalPrincipalLogin(_ context.Context, _ map[string]any) (*apiclient.ExternalPrincipal, error) {
	return nil, ErrNotImplemented
}

func (s *OIDCService) ValidateSTS(_ context.Context, _, _, _ string) (string, error) {
	return "", ErrNotImplemented
}

func (s *OIDCService) RegisterAdditionalRoutes(r *chi.Mux, sessionStore sessions.Store) {
	r.Get(OIDCLoginPath, s.loginHandler(sessionStore))
}

func (s *OIDCService) OauthCallback(w http.ResponseWriter, r *http.Request, sessionStore sessions.Store) {
	sessionStoreAdapter := oidcSessionStore{store: sessionStore}
	oidcSession, err := sessionStoreAdapter.Load(w, r)
	if err != nil {
		s.logger.WithError(err).Warn("OIDC callback session decode failed")
		redirectToLogin(w, r)
		return
	}

	transaction, err := oidcSession.Transaction()
	if err != nil {
		s.logger.WithError(err).Warn("OIDC callback missing or invalid login transaction")
		s.saveClearedTransaction(oidcSession)
		redirectToLogin(w, r)
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" || state != transaction.StateValue {
		s.logger.Warn("OIDC callback state mismatch")
		redirectToLogin(w, r)
		return
	}
	if err := transaction.validateCallbackState(state, time.Now()); err != nil {
		s.logger.WithError(err).Warn("OIDC callback transaction validation failed")
		s.saveClearedTransaction(oidcSession)
		redirectToLogin(w, r)
		return
	}
	if err := oidcSession.ClearTransactionAndSave(); err != nil {
		s.logger.WithError(err).Error("failed to consume OIDC transaction")
		redirectToLogin(w, r)
		return
	}

	if providerErr := r.URL.Query().Get("error"); providerErr != "" {
		s.logger.WithFields(logging.Fields{
			"error":             providerErr,
			"error_description": r.URL.Query().Get("error_description"),
		}).Warn("OIDC provider rejected login")
		redirectToLogin(w, r)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.logger.Warn("OIDC callback missing authorization code")
		redirectToLogin(w, r)
		return
	}

	claims, err := s.oidc.Exchange(r.Context(), transaction, oidcCallbackInput{State: state, Code: code})
	if err != nil {
		s.logger.WithError(err).Error("failed to exchange OIDC authorization code")
		redirectToLogin(w, r)
		return
	}
	normalizedClaims, err := normalizeOIDCClaims(claims, s.userClaimsConfig)
	if err != nil {
		s.logger.WithError(err).Error("failed to normalize OIDC claims")
		redirectToLogin(w, r)
		return
	}
	if err := oidcSession.SaveClaims(normalizedClaims); err != nil {
		s.logger.WithError(err).Error("failed to save OIDC session")
		redirectToLogin(w, r)
		return
	}
	http.Redirect(w, r, s.postLoginTarget(transaction.Next), http.StatusTemporaryRedirect)
}

func (s *OIDCService) loginHandler(sessionStore sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := auth.ClearSession(w, r, sessionStore, auth.InternalAuthSessionName); err != nil {
			s.logger.WithError(err).Error("failed to clear internal auth session")
			http.Error(w, "failed to prepare OIDC login", http.StatusInternalServerError)
			return
		}

		redirectURI, err := s.callbacks.RedirectURI(r)
		if err != nil {
			s.logger.WithError(err).Error("failed to resolve OIDC callback redirect URI")
			http.Error(w, "invalid OIDC callback configuration", http.StatusBadRequest)
			return
		}

		next := safePostLoginRedirect(r.URL.Query().Get("next"))
		transaction, authURL, err := s.oidc.BeginLogin(r.Context(), oidcBeginLoginInput{
			CallbackURL: redirectURI,
			Next:        next,
		})
		if err != nil {
			s.logger.WithError(err).Error("failed to create OIDC login")
			http.Error(w, "failed to prepare OIDC login", http.StatusInternalServerError)
			return
		}
		if err := (oidcSessionStore{store: sessionStore}).SaveTransaction(w, r, transaction); err != nil {
			s.logger.WithError(err).Error("failed to save OIDC login transaction")
			http.Error(w, "failed to prepare OIDC login", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}

func (s *OIDCService) postLoginTarget(next string) string {
	if safeNext := safePostLoginRedirect(next); safeNext != "" {
		return safeNext
	}
	if s.postLoginRedirectURL != "" {
		return s.postLoginRedirectURL
	}
	return oidcDefaultPostLoginTarget
}

func safePostLoginRedirect(raw string) string {
	return httputil.SafeRelativeRedirect(raw, "/auth/login", OIDCLoginPath, oidcCallbackPath)
}

func (s *OIDCService) saveClearedTransaction(session *oidcSession) {
	if err := session.ClearTransactionAndSave(); err != nil {
		s.logger.WithError(err).Error("failed to clear OIDC transaction")
	}
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/auth/login", http.StatusTemporaryRedirect)
}

func normalizeOIDCClaims(claims encoding.Claims, cfg config.OIDC) (encoding.Claims, error) {
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("%w: OIDC claims missing subject", ErrInvalidRequest)
	}
	normalized := encoding.Claims{"sub": sub}
	if issuer, ok := claims["iss"].(string); ok && issuer != "" {
		normalized["iss"] = issuer
	}
	copyConfiguredClaim(normalized, claims, cfg.FriendlyNameClaimName)
	copyConfiguredClaim(normalized, claims, cfg.EmailClaimName)
	copyConfiguredClaim(normalized, claims, cfg.InitialGroupsClaimName)
	for claimName := range cfg.ValidateIDTokenClaims {
		copyConfiguredClaim(normalized, claims, claimName)
	}
	return normalized, nil
}

func copyConfiguredClaim(dst, src encoding.Claims, claimName string) {
	if claimName == "" {
		return
	}
	if value, ok := src[claimName]; ok {
		dst[claimName] = value
	}
}
