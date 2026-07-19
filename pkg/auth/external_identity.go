package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/swag"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/logging"
)

// ExternalIdentity is the protocol-neutral user identity resolved from a
// verified external authentication exchange.
type ExternalIdentity struct {
	ExternalID   string
	Source       string
	FriendlyName string
	Email        string
}

type ExternalIdentityProvisioningOptions struct {
	PersistFriendlyName bool
}

// ResolveExternalUser resolves an existing lakeFS user by external ID. Existing
// users keep their current email and group memberships; only the effective
// friendly name may be updated.
func ResolveExternalUser(ctx context.Context, logger logging.Logger, authService Service, identity ExternalIdentity, options ExternalIdentityProvisioningOptions) (*model.User, bool, error) {
	if err := validateExternalIdentityID(identity); err != nil {
		return nil, false, err
	}
	log := externalIdentityLog(logger, identity)
	user, err := authService.GetUserByExternalID(ctx, identity.ExternalID)
	if err == nil {
		log.Info("Found user")
		return enhanceExternalUserFriendlyName(ctx, user, identity.FriendlyName, options.PersistFriendlyName, authService, logger), true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	log.WithError(err).Error("Failed to get external user from database")
	return nil, false, fmt.Errorf("get user by external ID: %w", err)
}

// ProvisionExternalUser creates a lakeFS user from a validated external
// identity and assigns creation-only initial groups. If group assignment fails,
// the newly created user is deleted best-effort before returning the error.
func ProvisionExternalUser(ctx context.Context, logger logging.Logger, authService Service, identity ExternalIdentity, initialGroups []string, options ExternalIdentityProvisioningOptions) (*model.User, error) {
	if err := validateExternalIdentityID(identity); err != nil {
		return nil, err
	}
	if err := validateInitialGroups(initialGroups); err != nil {
		return nil, err
	}

	log := externalIdentityLog(logger, identity)
	log.Info("User not found; creating them")
	newUser := model.User{
		CreatedAt:  time.Now().UTC(),
		Source:     identity.Source,
		Username:   identity.ExternalID,
		ExternalID: &identity.ExternalID,
	}
	if options.PersistFriendlyName {
		newUser.FriendlyName = &identity.FriendlyName
	}
	if identity.Email != "" {
		newUser.Email = &identity.Email
	}

	if _, err := authService.CreateUser(ctx, &newUser); err != nil {
		if !errors.Is(err, ErrAlreadyExists) {
			log.WithError(err).Error("Failed to create external user")
			return nil, fmt.Errorf("create user: %w", err)
		}
		user, err := authService.GetUserByExternalID(ctx, identity.ExternalID)
		if err != nil {
			log.WithError(err).Error("Failed to get external user after create race")
			return nil, fmt.Errorf("get user by external ID: %w", err)
		}
		return enhanceExternalUserFriendlyName(ctx, user, identity.FriendlyName, options.PersistFriendlyName, authService, logger), nil
	}

	if err := addInitialGroups(ctx, logger, authService, newUser.Username, initialGroups); err != nil {
		if deleteErr := authService.DeleteUser(ctx, newUser.Username); deleteErr != nil {
			log.WithError(errors.Join(err, deleteErr)).WithFields(logging.Fields{
				"username":       newUser.Username,
				"initial_groups": initialGroups,
			}).Error("External user provisioning rollback failed; delete the user or complete initial group membership before retrying login")
			return nil, errors.Join(
				err,
				fmt.Errorf("%w: user %q was created but initial group assignment and rollback failed: %w", ErrExternalUserProvisioningIncomplete, newUser.Username, deleteErr),
			)
		}
		return nil, err
	}

	return enhanceExternalUserFriendlyName(ctx, &newUser, identity.FriendlyName, false, authService, logger), nil
}

func externalIdentityLog(logger logging.Logger, identity ExternalIdentity) logging.Logger {
	return logger.WithFields(logging.Fields{
		"external_id":   identity.ExternalID,
		"source":        identity.Source,
		"friendly_name": identity.FriendlyName,
	})
}

func validateExternalIdentityID(identity ExternalIdentity) error {
	switch {
	case strings.TrimSpace(identity.ExternalID) == "":
		return fmt.Errorf("%w: external identity external ID is required", ErrAuthenticatingRequest)
	case strings.TrimSpace(identity.Source) == "":
		return fmt.Errorf("%w: external identity source is required", ErrAuthenticatingRequest)
	default:
		return nil
	}
}

func validateInitialGroups(groups []string) error {
	for _, groupName := range groups {
		if strings.TrimSpace(groupName) == "" {
			return fmt.Errorf("%w: external identity initial group name is required", ErrAuthenticatingRequest)
		}
	}
	return nil
}

func addInitialGroups(ctx context.Context, logger logging.Logger, authService Service, username string, initialGroups []string) error {
	for _, groupName := range initialGroups {
		if err := authService.AddUserToGroup(ctx, username, groupName); err != nil {
			if errors.Is(err, ErrAlreadyExists) {
				continue
			}
			logger.WithError(err).WithFields(logging.Fields{"group": groupName, "user": username}).Error("Failed to add external user to group")
			return fmt.Errorf("add user to initial group %q: %w", groupName, err)
		}
	}
	return nil
}

func enhanceExternalUserFriendlyName(ctx context.Context, user *model.User, friendlyName string, persistFriendlyName bool, authService Service, logger logging.Logger) *model.User {
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
