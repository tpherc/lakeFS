package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/logging"
)

// extractSecurityRequirements using Swagger returns an array of security requirements set for the request.
func extractSecurityRequirements(router routers.Router, r *http.Request) (openapi3.SecurityRequirements, error) {
	// Find route
	route, _, err := router.FindRoute(r)
	if err != nil {
		return nil, err
	}
	if route.Operation.Security == nil {
		return route.Spec.Security, nil
	}
	return *route.Operation.Security, nil
}

func GenericAuthMiddleware(logger logging.Logger, authenticator auth.Authenticator, authService auth.Service, externalIdentityProvisioner *auth.ExternalIdentityProvisioner, oidcConfig *auth.OIDCConfig, cookieAuthConfig *auth.CookieAuthConfig, secureCookies bool) (func(next http.Handler) http.Handler, error) {
	swagger, err := apigen.GetSwagger()
	if err != nil {
		return nil, err
	}
	sessionStore, err := auth.NewSessionStore(authService.SecretStore().SharedSecret(), auth.SessionStoreOptions{
		MaxAge: sessionMaxAge,
		Secure: secureCookies,
	})
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result, err := checkSecurityRequirements(w, r, swagger.Security, logger, authenticator, authService, externalIdentityProvisioner, sessionStore, oidcConfig, cookieAuthConfig)
			if err != nil {
				writeAuthError(w, r, err, http.StatusUnauthorized, ErrAuthenticatingRequest.Error())
				return
			}
			next.ServeHTTP(w, requestWithAuthentication(r, result))
		})
	}, nil
}

func AuthMiddleware(logger logging.Logger, swagger *openapi3.T, authenticator auth.Authenticator, authService auth.Service, externalIdentityProvisioner *auth.ExternalIdentityProvisioner, sessionStore sessions.Store, oidcConfig *auth.OIDCConfig, cookieAuthConfig *auth.CookieAuthConfig) func(next http.Handler) http.Handler {
	router, err := legacy.NewRouter(swagger)
	if err != nil {
		panic(err)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// if request already authenticated
			if _, userNotFoundErr := auth.GetUser(r.Context()); userNotFoundErr == nil {
				next.ServeHTTP(w, r)
				return
			}
			securityRequirements, err := extractSecurityRequirements(router, r)
			if err != nil {
				writeAuthError(w, r, err, http.StatusBadRequest, err.Error())
				return
			}
			result, err := checkSecurityRequirements(w, r, securityRequirements, logger, authenticator, authService, externalIdentityProvisioner, sessionStore, oidcConfig, cookieAuthConfig)
			if err != nil {
				writeAuthError(w, r, err, http.StatusUnauthorized, ErrAuthenticatingRequest.Error())
				return
			}
			next.ServeHTTP(w, requestWithAuthentication(r, result))
		})
	}
}

type authenticationResult struct {
	User          *model.User
	PrincipalTags principaltags.Tags
}

func requestWithAuthentication(r *http.Request, result *authenticationResult) *http.Request {
	if result == nil {
		return r
	}
	ctx := auth.WithUser(r.Context(), result.User)
	ctx = auth.WithPrincipalTags(ctx, result.PrincipalTags)
	ctx = logging.AddFields(ctx, logging.Fields{logging.UserFieldKey: result.User.Username})
	return r.WithContext(ctx)
}

// checkSecurityRequirements returns the complete authenticated principal, or nil
// when none of the request's credentials match the configured providers.
func checkSecurityRequirements(w http.ResponseWriter,
	r *http.Request,
	securityRequirements openapi3.SecurityRequirements,
	logger logging.Logger,
	authenticator auth.Authenticator,
	authService auth.Service,
	externalIdentityProvisioner *auth.ExternalIdentityProvisioner,
	sessionStore sessions.Store,
	oidcConfig *auth.OIDCConfig,
	cookieAuthConfig *auth.CookieAuthConfig,
) (*authenticationResult, error) {
	ctx := r.Context()
	logger = logger.WithContext(ctx)
	var firstSessionAuthErr error

	for _, securityRequirement := range securityRequirements {
		for provider := range securityRequirement {
			var (
				user        *model.User
				tags        principaltags.Tags
				sessionName string
				err         error
			)

			switch provider {
			case "jwt_token":
				authHeaderValue := r.Header.Get("Authorization")
				if authHeaderValue == "" {
					continue
				}
				parts := strings.Fields(authHeaderValue)
				if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
					continue
				}
				user, err = auth.UserByToken(ctx, authService, parts[1])
			case "basic_auth":
				accessKey, secretKey, ok := r.BasicAuth()
				if !ok {
					continue
				}
				user, err = auth.UserByAuth(ctx, authenticator, authService, accessKey, secretKey)
			case "cookie_auth":
				sessionName = auth.InternalAuthSessionName
				var internalAuthSession *sessions.Session
				internalAuthSession, err = loadAuthenticationSession(sessionStore, r, sessionName)
				if err != nil {
					break
				}
				token := ""
				if internalAuthSession != nil {
					token, _ = internalAuthSession.Values[auth.TokenSessionKeyName].(string)
				}
				if token == "" {
					continue
				}
				user, err = auth.UserByToken(ctx, authService, token)
				if err == nil && user != nil && auth.SessionNeedsEncodingUpgrade(internalAuthSession) {
					err = auth.SaveSession(r, w, internalAuthSession)
				}
			case "oidc_auth":
				sessionName = auth.OIDCAuthSessionName
				var oidcSession *sessions.Session
				oidcSession, err = loadAuthenticationSession(sessionStore, r, sessionName)
				if err != nil {
					break
				}
				var principal *auth.OIDCSessionAuthentication
				principal, err = auth.AuthenticateOIDCSession(ctx, logger, externalIdentityProvisioner, oidcSession, oidcConfig)
				if principal != nil {
					user, tags = principal.User, principal.PrincipalTags
				}
			case "saml_auth":
				sessionName = auth.SAMLAuthSessionName
				var samlSession *sessions.Session
				samlSession, err = loadAuthenticationSession(sessionStore, r, sessionName)
				if err != nil {
					break
				}
				user, err = auth.UserFromSAMLSession(ctx, logger, externalIdentityProvisioner, samlSession, cookieAuthConfig)
				if err == nil && user != nil && auth.SessionNeedsEncodingUpgrade(samlSession) {
					err = auth.SaveSession(r, w, samlSession)
				}
			default:
				logger.WithField("provider", provider).Error("Authentication middleware unknown security requirement provider")
				return nil, auth.ErrAuthenticatingRequest
			}

			if err != nil {
				if sessionName != "" && errors.Is(err, auth.ErrAuthenticatingRequest) {
					if firstSessionAuthErr == nil {
						firstSessionAuthErr = err
					}
					expireAuthenticationSession(w, r, sessionStore, sessionName, logger)
					continue
				}
				return nil, err
			}

			if user != nil {
				return &authenticationResult{User: user, PrincipalTags: tags}, nil
			}
		}
	}

	if firstSessionAuthErr != nil {
		return nil, firstSessionAuthErr
	}
	return nil, nil
}

func loadAuthenticationSession(store sessions.Store, r *http.Request, name string) (*sessions.Session, error) {
	session, err := store.Get(r, name)
	if err != nil && auth.IsSessionDecodeError(err) {
		return nil, fmt.Errorf("%w: %w", auth.ErrAuthenticatingRequest, err)
	}
	return session, err
}

func expireAuthenticationSession(w http.ResponseWriter, r *http.Request, store sessions.Store, name string, logger logging.Logger) {
	if err := auth.ClearSession(w, r, store, name); err != nil {
		logger.WithError(err).WithField("session_name", name).Warn("failed to expire authentication session")
	}
}

// writeAuthError centralizes error handling logic and avoids duplication
func writeAuthError(w http.ResponseWriter, r *http.Request, err error, defaultStatus int, defaultMsg string) {
	logging.FromContext(r.Context()).WithError(err).Warn("authentication error")
	// Only internal server errors are returned to the client to allow retries.
	// Other errors are masked to avoid exposing sensitive information.
	if errors.Is(err, auth.ErrInternalServerError) {
		writeError(w, r, http.StatusInternalServerError, auth.ErrInternalServerError)
	} else {
		writeError(w, r, defaultStatus, defaultMsg)
	}
}
