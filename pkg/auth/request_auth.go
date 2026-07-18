package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/swag"
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

func enhanceWithFriendlyName(ctx context.Context, user *model.User, friendlyName string, persistFriendlyName bool, authService Service, logger logging.Logger) *model.User {
	log := logger.WithFields(logging.Fields{"friendly_name": friendlyName, "persist_friendly_name": persistFriendlyName})
	if user == nil {
		log.Error("user is nil")
		return nil
	}
	if swag.StringValue(user.FriendlyName) != friendlyName {
		user.FriendlyName = swag.String(friendlyName)
		if persistFriendlyName {
			if err := authService.UpdateUserFriendlyName(ctx, user.Username, friendlyName); err != nil {
				log.WithError(err).Error("failed to update user friendly name")
			}
		}
	}
	return user
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

	user, err := authService.GetUserByExternalID(ctx, externalID)
	if err == nil {
		log.Info("Found user")
		return enhanceWithFriendlyName(ctx, user, friendlyName, cookieAuthConfig.PersistFriendlyName, authService, logger), nil
	}
	if !errors.Is(err, ErrNotFound) {
		log.WithError(err).Error("Failed while searching if user exists in database")
		return nil, fmt.Errorf("get user by external ID: %w", err)
	}
	log.Info("User not found; creating them")

	u := model.User{CreatedAt: time.Now().UTC(), Source: cookieAuthConfig.AuthSource, Username: externalID, ExternalID: &externalID}
	if cookieAuthConfig.PersistFriendlyName {
		u.FriendlyName = &friendlyName
	}
	_, err = authService.CreateUser(ctx, &u)
	if err != nil {
		if !errors.Is(err, ErrAlreadyExists) {
			log.WithError(err).Error("Failed to create external user in database")
			return nil, fmt.Errorf("create user: %w", err)
		}
		user, err = authService.GetUserByExternalID(ctx, externalID)
		if err != nil {
			log.WithError(err).Error("Failed to get external user from database")
			return nil, fmt.Errorf("get user by external ID: %w", err)
		}
		return enhanceWithFriendlyName(ctx, user, friendlyName, cookieAuthConfig.PersistFriendlyName, authService, logger), nil
	}

	groupsClaim := idTokenClaims[cookieAuthConfig.InitialGroupsClaimName]
	initialGroups, err := initialGroupsFromClaims(groupsClaim, cookieAuthConfig.DefaultInitialGroups)
	if err != nil {
		log.WithError(err).WithField("groups_claim", groupsClaim).Error("Failed to parse initial groups claim")
		return nil, ErrAuthenticatingRequest
	}
	for _, groupName := range initialGroups {
		err := authService.AddUserToGroup(ctx, u.Username, groupName)
		if err != nil {
			logger.WithError(err).WithFields(logging.Fields{"group": groupName, "user": u.Username}).Error("Failed to add external user to group")
		}
	}

	return enhanceWithFriendlyName(ctx, user, friendlyName, false, authService, logger), nil
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
	user, err := authService.GetUserByExternalID(ctx, externalID)
	if err == nil {
		return enhanceWithFriendlyName(ctx, user, friendlyName, oidcConfig.PersistFriendlyName, authService, logger), nil
	}
	if !errors.Is(err, ErrNotFound) {
		logger.WithError(err).Error("Failed to get external user from database")
		return nil, fmt.Errorf("get user by external ID: %w", err)
	}
	u := model.User{CreatedAt: time.Now().UTC(), Source: "oidc", Username: externalID, ExternalID: &externalID}
	if oidcConfig.PersistFriendlyName {
		u.FriendlyName = &friendlyName
	}
	if email != "" {
		u.Email = &email
	}
	_, err = authService.CreateUser(ctx, &u)
	if err != nil {
		if !errors.Is(err, ErrAlreadyExists) {
			logger.WithError(err).Error("Failed to create external user in database")
			return nil, fmt.Errorf("create user: %w", err)
		}
		user, err = authService.GetUserByExternalID(ctx, externalID)
		if err != nil {
			logger.WithError(err).Error("Failed to get external user from database")
			return nil, fmt.Errorf("get user by external ID: %w", err)
		}
		return enhanceWithFriendlyName(ctx, user, friendlyName, oidcConfig.PersistFriendlyName, authService, logger), nil
	}
	groupsClaim := idTokenClaims[oidcConfig.InitialGroupsClaimName]
	initialGroups, err := initialGroupsFromClaims(groupsClaim, oidcConfig.DefaultInitialGroups)
	if err != nil {
		logger.WithError(err).WithField("groups_claim", groupsClaim).Error("Failed to parse initial groups claim")
		return nil, ErrAuthenticatingRequest
	}
	for _, groupName := range initialGroups {
		err := authService.AddUserToGroup(ctx, u.Username, groupName)
		if err != nil {
			logger.WithError(err).WithFields(logging.Fields{"group": groupName, "user": u.Username}).Error("Failed to add external user to group")
		}
	}

	return enhanceWithFriendlyName(ctx, &u, friendlyName, false, authService, logger), nil
}

func oidcClaimsFromSession(authSession *sessions.Session) (oidcencoding.Claims, bool, error) {
	value := authSession.Values[IDTokenClaimsSessionKey]
	if value == nil {
		return nil, false, nil
	}
	switch claims := value.(type) {
	case oidcencoding.Claims:
		return claims, true, nil
	case string:
		if claims == "" {
			return nil, false, nil
		}
		var decoded oidcencoding.Claims
		if err := json.Unmarshal([]byte(claims), &decoded); err != nil {
			return nil, true, fmt.Errorf("decode OIDC claims: %w", err)
		}
		return decoded, true, nil
	default:
		return nil, true, fmt.Errorf("unexpected OIDC claims session value %T", value)
	}
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
