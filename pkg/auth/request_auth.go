package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth/model"
	oidcencoding "github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/logging"
)

const (
	TokenSessionKeyName       = "token"
	InternalAuthSessionName   = "internal_auth_session"
	IDTokenClaimsSessionKey   = "id_token_claims"
	OIDCAuthSessionName       = "oidc_auth_session"
	SAMLTokenClaimsSessionKey = "saml_token_claims"
	SAMLAuthSessionName       = "saml_auth_session"

	oidcClaimsSchemaVersionSessionKey = "_lakefs_oidc_claims_schema_version"
	oidcClaimsExpiresAtSessionKey     = "_lakefs_oidc_claims_expires_at"
	currentOIDCClaimsSchemaVersion    = 2
	oidcAuthSource                    = "oidc"
	defaultSAMLAuthSource             = "saml"
)

var ErrInvalidFormat = errors.New("invalid format")

type OIDCConfig struct {
	ValidateIDTokenClaims  map[string]string
	DefaultInitialGroups   []string
	InitialGroupsClaimName string
	FriendlyNameClaimName  string
	EmailClaimName         string
	PersistFriendlyName    bool
}

type CookieAuthConfig struct {
	ValidateIDTokenClaims   map[string]string
	DefaultInitialGroups    []string
	InitialGroupsClaimName  string
	FriendlyNameClaimName   string
	ExternalUserIDClaimName string
	AuthSource              string
	PersistFriendlyName     bool
}

func UserFromSAMLSession(ctx context.Context, logger logging.Logger, authService Service, authSession *sessions.Session, cookieAuthConfig *CookieAuthConfig) (*model.User, error) {
	idTokenClaims, ok := authSession.Values[SAMLTokenClaimsSessionKey].(oidcencoding.Claims)
	if idTokenClaims == nil {
		return nil, nil
	}
	if !ok {
		logger.WithField("claims", authSession.Values[SAMLTokenClaimsSessionKey]).Debug("failed decoding tokens")
		return nil, fmt.Errorf("getting token claims: %w", ErrAuthenticatingRequest)
	}
	logger.WithField("claims", idTokenClaims).Debug("Success decoding token claims")

	idKey := cookieAuthConfig.ExternalUserIDClaimName
	externalID, ok := idTokenClaims[idKey].(string)
	if !ok {
		logger.WithField(idKey, idTokenClaims[idKey]).Error("Failed type assertion for sub claim")
		return nil, ErrAuthenticatingRequest
	}

	log := logger.WithField("external_id", externalID)

	for claimName, expectedValue := range cookieAuthConfig.ValidateIDTokenClaims {
		actualValue, ok := idTokenClaims[claimName]
		if !ok || actualValue != expectedValue {
			log.WithFields(logging.Fields{
				"claim_name":     claimName,
				"actual_value":   actualValue,
				"expected_value": expectedValue,
				"missing":        !ok,
			}).Error("authentication failed on validating ID token claims")
			return nil, ErrAuthenticatingRequest
		}
	}

	friendlyName := ""
	if cookieAuthConfig.FriendlyNameClaimName != "" {
		friendlyName, _ = idTokenClaims[cookieAuthConfig.FriendlyNameClaimName].(string)
	}
	log = log.WithField("friendly_name", friendlyName)

	authSource := strings.TrimSpace(cookieAuthConfig.AuthSource)
	if authSource == "" {
		authSource = defaultSAMLAuthSource
	}
	identity := ExternalIdentity{
		ExternalID:   externalID,
		Source:       authSource,
		FriendlyName: friendlyName,
	}
	options := ExternalIdentityProvisioningOptions{PersistFriendlyName: cookieAuthConfig.PersistFriendlyName}
	user, found, err := ResolveExternalUser(ctx, logger, authService, identity, options)
	if err != nil || found {
		return user, err
	}

	groupsClaim := idTokenClaims[cookieAuthConfig.InitialGroupsClaimName]
	initialGroups, err := initialGroupsFromClaims(groupsClaim, cookieAuthConfig.DefaultInitialGroups)
	if err != nil {
		log.WithError(err).WithField("groups_claim", groupsClaim).Error("Failed to parse initial groups claim")
		return nil, ErrAuthenticatingRequest
	}
	return ProvisionExternalUser(ctx, logger, authService, identity, initialGroups, options)
}

func UserFromOIDCSession(ctx context.Context, logger logging.Logger, authService Service, authSession *sessions.Session, oidcConfig *OIDCConfig) (*model.User, error) {
	idTokenClaims, found, err := oidcClaimsFromSession(authSession, time.Now())
	if !found {
		return nil, nil
	}
	if err != nil {
		logger.WithError(err).Debug("failed decoding OIDC token claims")
		return nil, fmt.Errorf("%w: %w", ErrAuthenticatingRequest, err)
	}
	return ResolveOIDCUserFromClaims(ctx, logger, authService, idTokenClaims, oidcConfig)
}

// ResolveOIDCUserFromClaims resolves a previously provisioned OIDC user from
// minimized session claims. It intentionally does not provision users because
// creation-only claims are not kept in the long-lived browser session.
func ResolveOIDCUserFromClaims(ctx context.Context, logger logging.Logger, authService Service, idTokenClaims oidcencoding.Claims, oidcConfig *OIDCConfig) (*model.User, error) {
	identity, _, options, err := oidcIdentityFromClaims(logger, idTokenClaims, oidcConfig)
	if err != nil {
		return nil, err
	}
	user, found, err := ResolveExternalUser(ctx, logger, authService, identity, options)
	if err != nil {
		return nil, err
	}
	if !found {
		logger.WithField("external_id", identity.ExternalID).Error("OIDC user was not provisioned")
		return nil, ErrAuthenticatingRequest
	}
	return user, nil
}

// ResolveOrProvisionOIDCUserFromClaims resolves or provisions a lakeFS user
// from full verified OIDC claims during callback completion.
func ResolveOrProvisionOIDCUserFromClaims(ctx context.Context, logger logging.Logger, authService Service, idTokenClaims oidcencoding.Claims, oidcConfig *OIDCConfig) (*model.User, error) {
	identity, groupsClaim, options, err := oidcIdentityFromClaims(logger, idTokenClaims, oidcConfig)
	if err != nil {
		return nil, err
	}
	user, found, err := ResolveExternalUser(ctx, logger, authService, identity, options)
	if err != nil || found {
		return user, err
	}
	cfg := effectiveOIDCConfig(oidcConfig)
	initialGroups, err := initialGroupsFromClaims(groupsClaim, cfg.DefaultInitialGroups)
	if err != nil {
		logger.WithError(err).WithField("groups_claim", groupsClaim).Error("Failed to parse initial groups claim")
		return nil, ErrAuthenticatingRequest
	}
	return ProvisionExternalUser(ctx, logger, authService, identity, initialGroups, options)
}

func oidcIdentityFromClaims(logger logging.Logger, idTokenClaims oidcencoding.Claims, oidcConfig *OIDCConfig) (ExternalIdentity, any, ExternalIdentityProvisioningOptions, error) {
	cfg := effectiveOIDCConfig(oidcConfig)
	subject, ok := idTokenClaims["sub"].(string)
	if !ok || strings.TrimSpace(subject) == "" {
		logger.WithField("sub", idTokenClaims["sub"]).Error("Failed type assertion for sub claim")
		return ExternalIdentity{}, nil, ExternalIdentityProvisioningOptions{}, ErrAuthenticatingRequest
	}
	issuer, ok := idTokenClaims["iss"].(string)
	if !ok || strings.TrimSpace(issuer) == "" {
		logger.WithField("iss", idTokenClaims["iss"]).Error("Failed type assertion for issuer claim")
		return ExternalIdentity{}, nil, ExternalIdentityProvisioningOptions{}, ErrAuthenticatingRequest
	}
	externalID := oidcExternalID(issuer, subject)
	if err := ValidateOIDCRequiredClaims(idTokenClaims, cfg.ValidateIDTokenClaims); err != nil {
		logger.WithError(err).Error("Authentication failed on validating ID token claims")
		return ExternalIdentity{}, nil, ExternalIdentityProvisioningOptions{}, ErrAuthenticatingRequest
	}
	friendlyName := ""
	if cfg.FriendlyNameClaimName != "" {
		friendlyName, _ = idTokenClaims[cfg.FriendlyNameClaimName].(string)
	}
	email := ""
	if cfg.EmailClaimName != "" {
		email, _ = idTokenClaims[cfg.EmailClaimName].(string)
	}
	identity := ExternalIdentity{
		ExternalID:   externalID,
		Source:       oidcAuthSource,
		FriendlyName: friendlyName,
		Email:        email,
	}
	return identity, idTokenClaims[cfg.InitialGroupsClaimName], ExternalIdentityProvisioningOptions{PersistFriendlyName: cfg.PersistFriendlyName}, nil
}

func effectiveOIDCConfig(oidcConfig *OIDCConfig) OIDCConfig {
	if oidcConfig == nil {
		return OIDCConfig{}
	}
	return *oidcConfig
}

func ValidateOIDCRequiredClaims(idTokenClaims oidcencoding.Claims, requiredClaims map[string]string) error {
	for claimName, expectedValue := range requiredClaims {
		actualValue, ok := idTokenClaims[claimName]
		if !ok || actualValue != expectedValue {
			return fmt.Errorf("%w: OIDC claim %q did not match the configured value", ErrAuthenticatingRequest, claimName)
		}
	}
	return nil
}

// MarkOIDCSessionClaimsCurrent marks claims saved by the current normalized
// embedded OIDC callback schema and records the local lakeFS session expiry.
func MarkOIDCSessionClaimsCurrent(session *sessions.Session, expiresAt time.Time) {
	if session != nil {
		session.Values[oidcClaimsSchemaVersionSessionKey] = currentOIDCClaimsSchemaVersion
		session.Values[oidcClaimsExpiresAtSessionKey] = expiresAt.UTC().Unix()
	}
}

func oidcClaimsFromSession(authSession *sessions.Session, now time.Time) (oidcencoding.Claims, bool, error) {
	value := authSession.Values[IDTokenClaimsSessionKey]
	if value == nil {
		return nil, false, nil
	}
	if err := validateOIDCSessionClaimsCurrent(authSession, now); err != nil {
		return nil, true, err
	}
	claims, ok := value.(string)
	if !ok {
		return nil, true, fmt.Errorf("unexpected OIDC claims session value %T", value)
	}
	if claims == "" {
		return nil, false, nil
	}
	var decoded oidcencoding.Claims
	if err := json.Unmarshal([]byte(claims), &decoded); err != nil {
		return nil, true, fmt.Errorf("decode OIDC claims: %w", err)
	}
	return decoded, true, nil
}

func validateOIDCSessionClaimsCurrent(session *sessions.Session, now time.Time) error {
	version, ok := session.Values[oidcClaimsSchemaVersionSessionKey].(int)
	if !ok || version != currentOIDCClaimsSchemaVersion {
		return fmt.Errorf("OIDC claims session schema is not current")
	}
	expiresAt, ok := oidcSessionClaimsExpiresAt(session)
	if !ok {
		return fmt.Errorf("OIDC claims session expiry is missing")
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("%w: OIDC session expired", ErrSessionExpired)
	}
	return nil
}

func oidcSessionClaimsExpiresAt(session *sessions.Session) (time.Time, bool) {
	switch value := session.Values[oidcClaimsExpiresAtSessionKey].(type) {
	case int64:
		return time.Unix(value, 0), true
	case int:
		return time.Unix(int64(value), 0), true
	case float64:
		return time.Unix(int64(value), 0), true
	default:
		return time.Time{}, false
	}
}

func oidcExternalID(issuer, subject string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return oidcAuthSource + ":" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func initialGroupsFromClaims(groupsClaim any, defaultInitialGroups []string) ([]string, error) {
	if groupsClaim == nil {
		return normalizeInitialGroups(defaultInitialGroups), nil
	}
	groups := make([]string, 0)
	switch v := groupsClaim.(type) {
	case string:
		for item := range strings.SplitSeq(v, ",") {
			groups = append(groups, item)
		}
	case []string:
		groups = append(groups, v...)
	case []any:
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: initial groups must be strings", ErrInvalidFormat)
			}
			groups = append(groups, str)
		}
	default:
		return nil, fmt.Errorf("%w: initial groups claim must be a string or string array", ErrInvalidFormat)
	}
	return normalizeInitialGroups(groups), nil
}

func normalizeInitialGroups(groups []string) []string {
	normalized := make([]string, 0, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}
