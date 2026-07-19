package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/swag"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/kv"
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

const (
	externalIdentityProvisioningPrefix   = "externalIdentityProvisioning"
	externalIdentityProvisioningPending  = "pending"
	externalIdentityProvisioningComplete = "complete"
	externalIdentityProvisioningLeaseTTL = 10 * time.Minute
	externalIdentityProvisioningTokenLen = 24
)

//nolint:gochecknoinits
func init() {
	kv.MustRegisterType(model.PartitionKey, kv.FormatPath(externalIdentityProvisioningPrefix, "*"), nil)
}

type externalIdentityProvisioningRecord struct {
	State          string    `json:"state"`
	Username       string    `json:"username"`
	Source         string    `json:"source"`
	ExternalIDHash string    `json:"external_id_hash"`
	InitialGroups  []string  `json:"initial_groups"`
	OwnerToken     string    `json:"owner_token,omitempty"`
	Generation     int64     `json:"generation"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	LastError      string    `json:"last_error,omitempty"`
}

type externalIdentityProvisioningStore interface {
	Get(ctx context.Context, identity ExternalIdentity) (*externalIdentityProvisioningRecord, kv.Predicate, error)
	SetIf(ctx context.Context, identity ExternalIdentity, record *externalIdentityProvisioningRecord, predicate kv.Predicate) error
}

type kvExternalIdentityProvisioningStore struct {
	store kv.Store
}

type externalIdentityProvisioningLease struct {
	record    *externalIdentityProvisioningRecord
	predicate kv.Predicate
}

// ExternalIdentityProvisioner resolves and provisions external identities while
// hiding durable completion state from protocol-specific authentication code.
type ExternalIdentityProvisioner struct {
	authService Service
	store       externalIdentityProvisioningStore
	logger      logging.Logger
	now         func() time.Time
	ownerToken  func() (string, error)
}

func NewExternalIdentityProvisioner(authService Service, store kv.Store, logger logging.Logger) *ExternalIdentityProvisioner {
	return &ExternalIdentityProvisioner{
		authService: authService,
		store:       newKVExternalIdentityProvisioningStore(store),
		logger:      logger,
		now:         func() time.Time { return time.Now().UTC() },
		ownerToken:  newExternalIdentityProvisioningOwnerToken,
	}
}

func newKVExternalIdentityProvisioningStore(store kv.Store) externalIdentityProvisioningStore {
	if store == nil {
		return nil
	}
	return &kvExternalIdentityProvisioningStore{store: store}
}

// ResolveExternalUser resolves an existing lakeFS user by external ID. Existing
// users keep their current email and group memberships; only the effective
// friendly name may be updated.
func (p *ExternalIdentityProvisioner) ResolveExternalUser(ctx context.Context, identity ExternalIdentity, options ExternalIdentityProvisioningOptions) (*model.User, bool, error) {
	if err := validateExternalIdentityID(identity); err != nil {
		return nil, false, err
	}
	if p == nil || p.authService == nil {
		return nil, false, fmt.Errorf("%w: external identity provisioner is not configured", ErrInternalServerError)
	}
	if err := p.rejectPendingProvisioning(ctx, identity); err != nil {
		return nil, false, err
	}
	return p.resolveUser(ctx, identity, options)
}

// ResolveOrProvisionExternalUser resolves an existing user without parsing
// creation-only inputs. Only a missing user or stale pending record triggers
// provisioning from the stored initial-group snapshot.
func (p *ExternalIdentityProvisioner) ResolveOrProvisionExternalUser(ctx context.Context, identity ExternalIdentity, initialGroups func() ([]string, error), options ExternalIdentityProvisioningOptions) (*model.User, error) {
	if err := validateExternalIdentityID(identity); err != nil {
		return nil, err
	}
	if p == nil || p.authService == nil || p.store == nil {
		return nil, fmt.Errorf("%w: external identity provisioner is not configured", ErrInternalServerError)
	}

	record, predicate, err := p.store.Get(ctx, identity)
	switch {
	case err == nil && record.State == externalIdentityProvisioningPending:
		lease, err := p.takeOverStalePending(ctx, identity, record, predicate)
		if err != nil {
			return nil, err
		}
		return p.completeProvisioning(ctx, identity, lease, options)
	case err == nil && record.State == externalIdentityProvisioningComplete:
		user, found, err := p.resolveUser(ctx, identity, options)
		if err != nil || found {
			return user, err
		}
		return nil, fmt.Errorf("%w: completed external provisioning record has no user for source=%q external_id=%q", ErrAuthenticatingRequest, identity.Source, identity.ExternalID)
	case err == nil:
		return nil, fmt.Errorf("%w: invalid external provisioning state %q", ErrAuthenticatingRequest, record.State)
	case !errors.Is(err, kv.ErrNotFound):
		externalIdentityLog(p.logger, identity).WithError(err).Error("Failed to load external user provisioning state")
		return nil, fmt.Errorf("get external user provisioning state: %w", err)
	}

	user, found, err := p.resolveUser(ctx, identity, options)
	if err != nil || found {
		return user, err
	}
	groups, err := initialGroups()
	if err != nil {
		return nil, err
	}
	if err := validateInitialGroups(groups); err != nil {
		return nil, err
	}
	lease, err := p.acquirePending(ctx, identity, groups)
	if err != nil {
		return nil, err
	}
	return p.completeProvisioning(ctx, identity, lease, options)
}

func (p *ExternalIdentityProvisioner) resolveUser(ctx context.Context, identity ExternalIdentity, options ExternalIdentityProvisioningOptions) (*model.User, bool, error) {
	log := externalIdentityLog(p.logger, identity)
	user, err := p.authService.GetUserByExternalID(ctx, identity.ExternalID)
	if err == nil {
		log.Info("Found user")
		return enhanceExternalUserFriendlyName(ctx, user, identity.FriendlyName, options.PersistFriendlyName, p.authService, p.logger), true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	log.WithError(err).Error("Failed to get external user from database")
	return nil, false, fmt.Errorf("get user by external ID: %w", err)
}

func (p *ExternalIdentityProvisioner) completeProvisioning(ctx context.Context, identity ExternalIdentity, lease *externalIdentityProvisioningLease, options ExternalIdentityProvisioningOptions) (*model.User, error) {
	if lease == nil || lease.record == nil {
		return nil, fmt.Errorf("%w: external provisioning lease is required", ErrInternalServerError)
	}
	if lease.record.Source != identity.Source || lease.record.ExternalIDHash != externalIdentityProvisioningHash(identity) {
		return nil, fmt.Errorf("%w: external provisioning record does not match requested identity", ErrAuthenticatingRequest)
	}
	if err := validateInitialGroups(lease.record.InitialGroups); err != nil {
		return nil, err
	}

	log := externalIdentityLog(p.logger, identity)
	log.Info("User not found; creating them")
	newUser := model.User{
		CreatedAt:  p.now(),
		Source:     identity.Source,
		Username:   lease.record.Username,
		ExternalID: &identity.ExternalID,
	}
	if options.PersistFriendlyName {
		newUser.FriendlyName = &identity.FriendlyName
	}
	if identity.Email != "" {
		newUser.Email = &identity.Email
	}

	user := &newUser
	created := true
	if _, err := p.authService.CreateUser(ctx, &newUser); err != nil {
		if !errors.Is(err, ErrAlreadyExists) {
			return nil, p.provisioningFailure(ctx, identity, lease, fmt.Errorf("create user: %w", err))
		}
		winner, err := p.authService.GetUserByExternalID(ctx, identity.ExternalID)
		if err != nil {
			return nil, p.provisioningFailure(ctx, identity, lease, fmt.Errorf("get user by external ID: %w", err))
		}
		user = winner
		created = false
	}

	for _, groupName := range lease.record.InitialGroups {
		var err error
		lease, err = p.renewLease(ctx, identity, lease)
		if err != nil {
			return nil, err
		}
		if err := addInitialGroup(ctx, p.logger, p.authService, user.Username, groupName); err != nil {
			return nil, p.provisioningFailure(ctx, identity, lease, err)
		}
	}
	if _, err := p.completeLease(ctx, identity, lease); err != nil {
		return nil, err
	}

	return enhanceExternalUserFriendlyName(ctx, user, identity.FriendlyName, options.PersistFriendlyName && !created, p.authService, p.logger), nil
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

func addInitialGroup(ctx context.Context, logger logging.Logger, authService Service, username string, groupName string) error {
	if err := authService.AddUserToGroup(ctx, username, groupName); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return nil
		}
		logger.WithError(err).WithFields(logging.Fields{"group": groupName, "user": username}).Error("Failed to add external user to group")
		return fmt.Errorf("add user to initial group %q: %w", groupName, err)
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

func (p *ExternalIdentityProvisioner) rejectPendingProvisioning(ctx context.Context, identity ExternalIdentity) error {
	if p.store == nil {
		return nil
	}
	record, _, err := p.store.Get(ctx, identity)
	if errors.Is(err, kv.ErrNotFound) {
		return nil
	}
	if err != nil {
		externalIdentityLog(p.logger, identity).WithError(err).Error("Failed to load external user provisioning state")
		return fmt.Errorf("get external user provisioning state: %w", err)
	}
	if record.State == externalIdentityProvisioningPending {
		return provisioningIncompleteError(identity, record.Username, "external user provisioning is still pending; retry after provisioning completes")
	}
	return nil
}

func (p *ExternalIdentityProvisioner) acquirePending(ctx context.Context, identity ExternalIdentity, initialGroups []string) (*externalIdentityProvisioningLease, error) {
	owner, err := p.ownerToken()
	if err != nil {
		return nil, err
	}
	now := p.now()
	record := &externalIdentityProvisioningRecord{
		State:          externalIdentityProvisioningPending,
		Username:       identity.ExternalID,
		Source:         identity.Source,
		ExternalIDHash: externalIdentityProvisioningHash(identity),
		InitialGroups:  append([]string(nil), initialGroups...),
		OwnerToken:     owner,
		Generation:     1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := p.store.SetIf(ctx, identity, record, nil); err != nil {
		if errors.Is(err, kv.ErrPredicateFailed) {
			loaded, predicate, loadErr := p.store.Get(ctx, identity)
			if loadErr != nil {
				return nil, fmt.Errorf("get external user provisioning state after acquire race: %w", loadErr)
			}
			if loaded.State == externalIdentityProvisioningPending {
				return p.takeOverStalePending(ctx, identity, loaded, predicate)
			}
			return nil, provisioningIncompleteError(identity, loaded.Username, "external user provisioning was completed by another worker; retry login")
		}
		return nil, fmt.Errorf("create external user provisioning state: %w", err)
	}
	record, predicate, err := p.store.Get(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("get external user provisioning state after acquire: %w", err)
	}
	return &externalIdentityProvisioningLease{record: record, predicate: predicate}, nil
}

func (p *ExternalIdentityProvisioner) takeOverStalePending(ctx context.Context, identity ExternalIdentity, record *externalIdentityProvisioningRecord, predicate kv.Predicate) (*externalIdentityProvisioningLease, error) {
	if record.State != externalIdentityProvisioningPending {
		return nil, fmt.Errorf("%w: external provisioning state %q is not pending", ErrAuthenticatingRequest, record.State)
	}
	if p.now().Sub(record.UpdatedAt) < externalIdentityProvisioningLeaseTTL {
		return nil, provisioningIncompleteError(identity, record.Username, "external user provisioning is already in progress; retry after provisioning completes")
	}
	owner, err := p.ownerToken()
	if err != nil {
		return nil, err
	}
	next := *record
	next.OwnerToken = owner
	next.Generation++
	next.UpdatedAt = p.now()
	next.LastError = ""
	if err := p.store.SetIf(ctx, identity, &next, predicate); err != nil {
		if errors.Is(err, kv.ErrPredicateFailed) {
			return nil, provisioningIncompleteError(identity, record.Username, "external user provisioning was updated by another worker; retry login")
		}
		return nil, fmt.Errorf("take over external user provisioning state: %w", err)
	}
	loaded, nextPredicate, err := p.store.Get(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("get external user provisioning state after takeover: %w", err)
	}
	if loaded.OwnerToken != owner || loaded.Generation != next.Generation {
		return nil, provisioningIncompleteError(identity, loaded.Username, "external user provisioning was taken by another worker; retry login")
	}
	return &externalIdentityProvisioningLease{record: loaded, predicate: nextPredicate}, nil
}

func (p *ExternalIdentityProvisioner) renewLease(ctx context.Context, identity ExternalIdentity, lease *externalIdentityProvisioningLease) (*externalIdentityProvisioningLease, error) {
	next := *lease.record
	next.UpdatedAt = p.now()
	if err := p.store.SetIf(ctx, identity, &next, lease.predicate); err != nil {
		if errors.Is(err, kv.ErrPredicateFailed) {
			return nil, provisioningIncompleteError(identity, lease.record.Username, "external user provisioning ownership changed; retry login")
		}
		return nil, fmt.Errorf("renew external user provisioning state: %w", err)
	}
	loaded, predicate, err := p.store.Get(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("get external user provisioning state after renew: %w", err)
	}
	if loaded.OwnerToken != lease.record.OwnerToken || loaded.Generation != lease.record.Generation {
		return nil, provisioningIncompleteError(identity, loaded.Username, "external user provisioning ownership changed; retry login")
	}
	return &externalIdentityProvisioningLease{record: loaded, predicate: predicate}, nil
}

func (p *ExternalIdentityProvisioner) completeLease(ctx context.Context, identity ExternalIdentity, lease *externalIdentityProvisioningLease) (*externalIdentityProvisioningLease, error) {
	next := *lease.record
	next.State = externalIdentityProvisioningComplete
	next.OwnerToken = ""
	next.UpdatedAt = p.now()
	next.LastError = ""
	if err := p.store.SetIf(ctx, identity, &next, lease.predicate); err != nil {
		if errors.Is(err, kv.ErrPredicateFailed) {
			return nil, provisioningIncompleteError(identity, lease.record.Username, "external user provisioning ownership changed before completion; retry login")
		}
		return nil, fmt.Errorf("complete external user provisioning state: %w", err)
	}
	loaded, predicate, err := p.store.Get(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("get external user provisioning state after completion: %w", err)
	}
	return &externalIdentityProvisioningLease{record: loaded, predicate: predicate}, nil
}

func (p *ExternalIdentityProvisioner) provisioningFailure(ctx context.Context, identity ExternalIdentity, lease *externalIdentityProvisioningLease, cause error) error {
	next := *lease.record
	next.State = externalIdentityProvisioningPending
	next.UpdatedAt = p.now()
	next.LastError = cause.Error()
	if err := p.store.SetIf(ctx, identity, &next, lease.predicate); err != nil && !errors.Is(err, kv.ErrPredicateFailed) {
		externalIdentityLog(p.logger, identity).WithError(err).Error("Failed to record external user provisioning failure")
	}
	externalIdentityLog(p.logger, identity).WithError(cause).WithFields(logging.Fields{
		"username":       lease.record.Username,
		"initial_groups": lease.record.InitialGroups,
	}).Error("External user provisioning incomplete; user authentication is blocked until initial group membership is completed")
	return errors.Join(cause, provisioningIncompleteError(identity, lease.record.Username, "retry login after the group backend recovers or complete the listed group memberships manually"))
}

func provisioningIncompleteError(identity ExternalIdentity, username string, guidance string) error {
	return fmt.Errorf("%w: source=%q external_id=%q username=%q: %s", ErrExternalUserProvisioningIncomplete, identity.Source, identity.ExternalID, username, guidance)
}

func externalIdentityProvisioningKey(identity ExternalIdentity) []byte {
	return []byte(kv.FormatPath(externalIdentityProvisioningPrefix, externalIdentityProvisioningHash(identity)))
}

func externalIdentityProvisioningHash(identity ExternalIdentity) string {
	sum := sha256.Sum256([]byte(identity.Source + "\x00" + identity.ExternalID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newExternalIdentityProvisioningOwnerToken() (string, error) {
	token := make([]byte, externalIdentityProvisioningTokenLen)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate external identity provisioning owner token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s *kvExternalIdentityProvisioningStore) Get(ctx context.Context, identity ExternalIdentity) (*externalIdentityProvisioningRecord, kv.Predicate, error) {
	value, err := s.store.Get(ctx, []byte(model.PartitionKey), externalIdentityProvisioningKey(identity))
	if err != nil {
		return nil, nil, err
	}
	var record externalIdentityProvisioningRecord
	if err := json.Unmarshal(value.Value, &record); err != nil {
		return nil, nil, fmt.Errorf("decode external identity provisioning record: %w", err)
	}
	return &record, value.Predicate, nil
}

func (s *kvExternalIdentityProvisioningStore) SetIf(ctx context.Context, identity ExternalIdentity, record *externalIdentityProvisioningRecord, predicate kv.Predicate) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.store.SetIf(ctx, []byte(model.PartitionKey), externalIdentityProvisioningKey(identity), data, predicate)
}
