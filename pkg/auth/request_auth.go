package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	currentOIDCClaimsSchemaVersion    = 1
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

	groupsClaim := idTokenClaims[cookieAuthConfig.InitialGroupsClaimName]
	initialGroups, err := initialGroupsFromClaims(groupsClaim, cookieAuthConfig.DefaultInitialGroups)
	if err != nil {
		log.WithError(err).WithField("groups_claim", groupsClaim).Error("Failed to parse initial groups claim")
		return nil, ErrAuthenticatingRequest
	}

	authSource := strings.TrimSpace(cookieAuthConfig.AuthSource)
	if authSource == "" {
		authSource = defaultSAMLAuthSource
	}
	return ResolveOrProvisionExternalUser(ctx, logger, authService, ExternalIdentity{
		ExternalID:    externalID,
		Source:        authSource,
		FriendlyName:  friendlyName,
		InitialGroups: initialGroups,
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: cookieAuthConfig.PersistFriendlyName})
}

func UserFromOIDCSession(ctx context.Context, logger logging.Logger, authService Service, authSession *sessions.Session, oidcConfig *OIDCConfig) (*model.User, error) {
	idTokenClaims, found, err := oidcClaimsFromSession(authSession)
	if !found {
		return nil, nil
	}
	if err != nil {
		logger.WithError(err).Debug("failed decoding OIDC token claims")
		return nil, ErrAuthenticatingRequest
	}
	externalID, ok := idTokenClaims["sub"].(string)
	if !ok {
		logger.WithField("sub", idTokenClaims["sub"]).Error("Failed type assertion for sub claim")
		return nil, ErrAuthenticatingRequest
	}
	for claimName, expectedValue := range oidcConfig.ValidateIDTokenClaims {
		actualValue, ok := idTokenClaims[claimName]
		if !ok || actualValue != expectedValue {
			logger.WithFields(logging.Fields{
				"claim_name":     claimName,
				"actual_value":   actualValue,
				"expected_value": expectedValue,
				"missing":        !ok,
			}).Error("Authentication failed on validating ID token claims")
			return nil, ErrAuthenticatingRequest
		}
	}
	friendlyName := ""
	if oidcConfig.FriendlyNameClaimName != "" {
		friendlyName, _ = idTokenClaims[oidcConfig.FriendlyNameClaimName].(string)
	}
	email := ""
	if oidcConfig.EmailClaimName != "" {
		email, _ = idTokenClaims[oidcConfig.EmailClaimName].(string)
	}
	groupsClaim := idTokenClaims[oidcConfig.InitialGroupsClaimName]
	initialGroups, err := initialGroupsFromClaims(groupsClaim, oidcConfig.DefaultInitialGroups)
	if err != nil {
		logger.WithError(err).WithField("groups_claim", groupsClaim).Error("Failed to parse initial groups claim")
		return nil, ErrAuthenticatingRequest
	}

	return ResolveOrProvisionExternalUser(ctx, logger, authService, ExternalIdentity{
		ExternalID:    externalID,
		Source:        "oidc",
		FriendlyName:  friendlyName,
		Email:         email,
		InitialGroups: initialGroups,
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: oidcConfig.PersistFriendlyName})
}

// MarkOIDCSessionClaimsCurrent marks claims saved by the current normalized OIDC callback schema.
func MarkOIDCSessionClaimsCurrent(session *sessions.Session) {
	if session != nil {
		session.Values[oidcClaimsSchemaVersionSessionKey] = currentOIDCClaimsSchemaVersion
	}
}

func oidcClaimsFromSession(authSession *sessions.Session) (oidcencoding.Claims, bool, error) {
	value := authSession.Values[IDTokenClaimsSessionKey]
	if value == nil {
		return nil, false, nil
	}
	if !oidcSessionClaimsCurrent(authSession) {
		return nil, true, fmt.Errorf("OIDC claims session schema is not current")
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

func oidcSessionClaimsCurrent(session *sessions.Session) bool {
	version, ok := session.Values[oidcClaimsSchemaVersionSessionKey].(int)
	return ok && version == currentOIDCClaimsSchemaVersion
}

func initialGroupsFromClaims(groupsClaim any, defaultInitialGroups []string) ([]string, error) {
	if groupsClaim == nil {
		return append([]string(nil), defaultInitialGroups...), nil
	}
	groups := make([]string, 0)
	seen := make(map[string]struct{})
	switch v := groupsClaim.(type) {
	case string:
		for item := range strings.SplitSeq(v, ",") {
			groups = appendInitialGroup(groups, seen, item)
		}
	case []string:
		for _, item := range v {
			groups = appendInitialGroup(groups, seen, item)
		}
	case []any:
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: initial groups must be strings", ErrInvalidFormat)
			}
			groups = appendInitialGroup(groups, seen, str)
		}
	default:
		return nil, fmt.Errorf("%w: initial groups claim must be a string or string array", ErrInvalidFormat)
	}
	return groups, nil
}

func appendInitialGroup(groups []string, seen map[string]struct{}, group string) []string {
	trimmed := strings.TrimSpace(group)
	if trimmed == "" {
		return groups
	}
	if _, ok := seen[trimmed]; ok {
		return groups
	}
	seen[trimmed] = struct{}{}
	return append(groups, trimmed)
}
