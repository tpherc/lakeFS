package authentication

import (
	"context"
	"errors"
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
	authService          auth.Service
	userClaimsConfig     config.OIDC
	sessionDuration      time.Duration
	postLoginRedirectURL string
	logoutRedirectURL    string
	logger               logging.Logger
}

func NewOIDCService(ctx context.Context, authService auth.Service, providerConfig config.OIDCProvider, userClaimsConfig config.OIDC, sessionDuration time.Duration, logoutRedirectURL string, logger logging.Logger) (*OIDCService, error) {
	compiledLogoutURL, err := compileOIDCLogoutURL(logoutRedirectURL, providerConfig)
	if err != nil {
		return nil, err
	}
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
		authService:          authService,
		userClaimsConfig:     userClaimsConfig,
		sessionDuration:      sessionDuration,
		postLoginRedirectURL: providerConfig.PostLoginRedirectURL,
		logoutRedirectURL:    compiledLogoutURL,
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

func (s *OIDCService) LogoutRedirectURL() string {
	return s.logoutRedirectURL
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
	authOIDCConfig := oidcAuthConfig(s.userClaimsConfig)
	if err := auth.ValidateOIDCRequiredClaims(claims, authOIDCConfig.ValidateIDTokenClaims); err != nil {
		s.logger.WithError(err).Warn("OIDC required claim validation failed")
		redirectToLogin(w, r)
		return
	}
	if _, err := auth.ResolveOrProvisionOIDCUserFromClaims(r.Context(), s.logger, s.authService, claims, &authOIDCConfig); err != nil {
		s.logger.WithError(err).Error("failed to resolve or provision OIDC user")
		redirectToLogin(w, r)
		return
	}
	normalizedClaims, err := normalizeOIDCClaims(claims, s.userClaimsConfig)
	if err != nil {
		s.logger.WithError(err).Error("failed to normalize OIDC claims")
		redirectToLogin(w, r)
		return
	}
	expiresAt := time.Now().Add(s.sessionDuration)
	if err := oidcSession.SaveClaims(normalizedClaims, expiresAt); err != nil {
		s.logger.WithError(err).Error("failed to save OIDC session")
		redirectToLogin(w, r)
		return
	}
	http.Redirect(w, r, s.postLoginTarget(transaction.Next), http.StatusFound)
}

func (s *OIDCService) loginHandler(sessionStore sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.clearLoginSessions(w, r, sessionStore); err != nil {
			s.logger.WithError(err).Error("failed to clear existing auth sessions")
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

func (s *OIDCService) clearLoginSessions(w http.ResponseWriter, r *http.Request, sessionStore sessions.Store) error {
	var errs []error
	for _, sessionName := range []string{auth.InternalAuthSessionName, auth.SAMLAuthSessionName} {
		if err := auth.ClearSession(w, r, sessionStore, sessionName); err != nil {
			s.logger.WithError(err).WithField("session", sessionName).Error("failed to clear auth session before OIDC login")
			errs = append(errs, fmt.Errorf("%s: %w", sessionName, err))
		}
	}
	return errors.Join(errs...)
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
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

func normalizeOIDCClaims(claims encoding.Claims, cfg config.OIDC) (encoding.Claims, error) {
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("%w: OIDC claims missing subject", ErrInvalidRequest)
	}
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return nil, fmt.Errorf("%w: OIDC claims missing issuer", ErrInvalidRequest)
	}
	normalized := encoding.Claims{
		"iss": issuer,
		"sub": sub,
	}
	copyConfiguredClaim(normalized, claims, cfg.FriendlyNameClaimName)
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

func oidcAuthConfig(cfg config.OIDC) auth.OIDCConfig {
	return auth.OIDCConfig{
		ValidateIDTokenClaims:  cfg.ValidateIDTokenClaims,
		DefaultInitialGroups:   cfg.DefaultInitialGroups,
		InitialGroupsClaimName: cfg.InitialGroupsClaimName,
		FriendlyNameClaimName:  cfg.FriendlyNameClaimName,
		EmailClaimName:         cfg.EmailClaimName,
		PersistFriendlyName:    cfg.PersistFriendlyName,
	}
}
