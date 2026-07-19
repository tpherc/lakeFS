package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
)

type externalIdentityAuthService struct {
	Service
	mu                sync.Mutex
	usersByExternalID map[string]*model.User

	createRequests      []*model.User
	addedGroups         []externalGroupMembership
	deletedUsers        []string
	friendlyNameUpdates []externalFriendlyNameUpdate
	getUserCalls        int

	getUserByExternalErr error
	createUserErr        error
	createRaceWinner     *model.User
	addUserToGroupErr    error
	deleteUserErr        error

	afterGetUserByExternalID func(externalID string, call int)
	beforeAddUserToGroup     func(username, groupID string, call int)
	addUserToGroupCalls      int
}

type externalGroupMembership struct {
	username string
	groupID  string
}

type externalFriendlyNameUpdate struct {
	username     string
	friendlyName string
}

func newExternalIdentityAuthService(users ...*model.User) *externalIdentityAuthService {
	s := &externalIdentityAuthService{usersByExternalID: make(map[string]*model.User)}
	for _, user := range users {
		if user.ExternalID != nil {
			s.usersByExternalID[*user.ExternalID] = cloneUser(user)
		}
	}
	return s
}

func newExternalIdentityProvisionerForTest(t *testing.T, authService *externalIdentityAuthService) *ExternalIdentityProvisioner {
	t.Helper()
	provisioner := NewExternalIdentityProvisioner(
		authService,
		kvtest.GetStore(t.Context(), t),
		logging.ContextUnavailable(),
	)
	var ownerSeq int
	provisioner.ownerToken = func() (string, error) {
		ownerSeq++
		return fmt.Sprintf("owner-%d", ownerSeq), nil
	}
	return provisioner
}

func resolveOrProvisionForTest(t *testing.T, provisioner *ExternalIdentityProvisioner, identity ExternalIdentity, groups []string, options ExternalIdentityProvisioningOptions) (*model.User, error) {
	t.Helper()
	return provisioner.ResolveOrProvisionExternalUser(t.Context(), identity, func() ([]string, error) {
		return groups, nil
	}, options)
}

func (s *externalIdentityAuthService) GetUserByExternalID(_ context.Context, externalID string) (*model.User, error) {
	s.mu.Lock()
	s.getUserCalls++
	call := s.getUserCalls
	getErr := s.getUserByExternalErr
	user := cloneUser(s.usersByExternalID[externalID])
	hook := s.afterGetUserByExternalID
	s.mu.Unlock()

	if hook != nil {
		hook(externalID, call)
	}
	if getErr != nil {
		return nil, getErr
	}
	if user == nil {
		return nil, ErrNotFound
	}
	return user, nil
}

func (s *externalIdentityAuthService) CreateUser(_ context.Context, user *model.User) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createRequests = append(s.createRequests, cloneUser(user))
	if s.createUserErr != nil {
		if errors.Is(s.createUserErr, ErrAlreadyExists) && s.createRaceWinner != nil && s.createRaceWinner.ExternalID != nil {
			s.usersByExternalID[*s.createRaceWinner.ExternalID] = cloneUser(s.createRaceWinner)
		}
		return "", s.createUserErr
	}
	copied := cloneUser(user)
	if copied.ExternalID != nil {
		if _, ok := s.usersByExternalID[*copied.ExternalID]; ok {
			return "", ErrAlreadyExists
		}
		s.usersByExternalID[*copied.ExternalID] = cloneUser(copied)
	}
	return user.Username, nil
}

func (s *externalIdentityAuthService) AddUserToGroup(_ context.Context, username, groupID string) error {
	s.mu.Lock()
	s.addUserToGroupCalls++
	call := s.addUserToGroupCalls
	hook := s.beforeAddUserToGroup
	s.mu.Unlock()

	if hook != nil {
		hook(username, groupID, call)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.addedGroups = append(s.addedGroups, externalGroupMembership{username: username, groupID: groupID})
	return s.addUserToGroupErr
}

func (s *externalIdentityAuthService) DeleteUser(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletedUsers = append(s.deletedUsers, username)
	if s.deleteUserErr != nil {
		return s.deleteUserErr
	}
	for externalID, user := range s.usersByExternalID {
		if user.Username == username {
			delete(s.usersByExternalID, externalID)
		}
	}
	return nil
}

func (s *externalIdentityAuthService) UpdateUserFriendlyName(_ context.Context, username, friendlyName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.friendlyNameUpdates = append(s.friendlyNameUpdates, externalFriendlyNameUpdate{
		username:     username,
		friendlyName: friendlyName,
	})
	for _, user := range s.usersByExternalID {
		if user.Username == username {
			user.FriendlyName = &friendlyName
		}
	}
	return nil
}

func TestProvisionExternalUserCreatesUserAndAssignsInitialGroups(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)

	user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
		ExternalID:   "alice",
		Source:       "oidc",
		FriendlyName: "Alice Example",
		Email:        "alice@example.com",
	}, []string{"Developers", "Viewers"}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.NoError(t, err)

	require.Equal(t, "alice", user.Username)
	require.Equal(t, "oidc", user.Source)
	require.Equal(t, "alice", stringValue(user.ExternalID))
	require.Equal(t, "Alice Example", stringValue(user.FriendlyName))
	require.Equal(t, "alice@example.com", stringValue(user.Email))
	require.False(t, user.CreatedAt.IsZero())

	require.Len(t, authService.createRequests, 1)
	created := authService.createRequests[0]
	require.Equal(t, "alice", created.Username)
	require.Equal(t, "oidc", created.Source)
	require.Equal(t, "alice", stringValue(created.ExternalID))
	require.Equal(t, "Alice Example", stringValue(created.FriendlyName))
	require.Equal(t, "alice@example.com", stringValue(created.Email))
	require.Equal(t, []externalGroupMembership{
		{username: "alice", groupID: "Developers"},
		{username: "alice", groupID: "Viewers"},
	}, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
}

func TestResolveExternalUserExistingUserUpdatesFriendlyNameOnly(t *testing.T) {
	authService := newExternalIdentityAuthService(&model.User{
		Username:     "bob",
		ExternalID:   stringPtr("bob"),
		Source:       "oidc",
		FriendlyName: stringPtr("Old Name"),
		Email:        stringPtr("old@example.com"),
	})
	provisioner := newExternalIdentityProvisionerForTest(t, authService)

	user, found, err := provisioner.ResolveExternalUser(t.Context(), ExternalIdentity{
		ExternalID:   "bob",
		Source:       "oidc",
		FriendlyName: "Bob New",
		Email:        "new@example.com",
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.NoError(t, err)
	require.True(t, found)

	require.Equal(t, "bob", user.Username)
	require.Equal(t, "Bob New", stringValue(user.FriendlyName))
	require.Equal(t, "old@example.com", stringValue(user.Email))
	require.Empty(t, authService.createRequests)
	require.Empty(t, authService.addedGroups)
	require.Equal(t, []externalFriendlyNameUpdate{{username: "bob", friendlyName: "Bob New"}}, authService.friendlyNameUpdates)
}

func TestResolveExternalUserNotFoundDoesNotMutate(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)

	user, found, err := provisioner.ResolveExternalUser(t.Context(), ExternalIdentity{
		ExternalID:   "alice",
		Source:       "oidc",
		FriendlyName: "Alice New",
		Email:        "alice@example.com",
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, user)
	require.Empty(t, authService.createRequests)
	require.Empty(t, authService.addedGroups)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestProvisionExternalUserReturnsFriendlyNameWithoutPersisting(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)

	user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
		ExternalID:   "brenda",
		Source:       "oidc",
		FriendlyName: "Brenda Viewer",
	}, nil, ExternalIdentityProvisioningOptions{PersistFriendlyName: false})
	require.NoError(t, err)

	require.Equal(t, "Brenda Viewer", stringValue(user.FriendlyName))
	require.Len(t, authService.createRequests, 1)
	require.Empty(t, stringValue(authService.createRequests[0].FriendlyName))
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestProvisionExternalUserCreateRaceFetchesWinner(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	authService.createUserErr = ErrAlreadyExists
	authService.createRaceWinner = &model.User{
		Username:     "race-winner",
		ExternalID:   stringPtr("carol"),
		Source:       "oidc",
		FriendlyName: stringPtr("Carol Winner"),
	}

	user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
		ExternalID:   "carol",
		Source:       "oidc",
		FriendlyName: "Carol Winner",
	}, []string{"Developers"}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.NoError(t, err)

	require.Equal(t, "race-winner", user.Username)
	require.Len(t, authService.createRequests, 1)
	require.Equal(t, []externalGroupMembership{{username: "race-winner", groupID: "Developers"}}, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
}

func TestProvisionExternalUserCreateFailureWrapsInternalServerError(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	createErr := errors.New("create user storage unavailable")
	authService.createUserErr = createErr

	user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
		ExternalID: "carol",
		Source:     "oidc",
	}, []string{"Developers"}, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, createErr)
	require.ErrorIs(t, err, ErrInternalServerError)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Len(t, authService.createRequests, 1)
	require.Empty(t, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
}

func TestProvisionExternalUserCreateRaceFetchFailureWrapsInternalServerError(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	fetchErr := errors.New("fetch race winner failed")
	authService.createUserErr = ErrAlreadyExists
	authService.afterGetUserByExternalID = func(externalID string, call int) {
		if externalID == "carol" && call == 1 {
			authService.mu.Lock()
			authService.getUserByExternalErr = fetchErr
			authService.mu.Unlock()
		}
	}

	user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
		ExternalID: "carol",
		Source:     "oidc",
	}, []string{"Developers"}, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, fetchErr)
	require.ErrorIs(t, err, ErrInternalServerError)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Len(t, authService.createRequests, 1)
	require.Empty(t, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
}

func TestProvisionExternalUserGroupAlreadyExistsIsSuccess(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	authService.addUserToGroupErr = ErrAlreadyExists

	user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
		ExternalID: "dave",
		Source:     "oidc",
	}, []string{"Developers"}, ExternalIdentityProvisioningOptions{})
	require.NoError(t, err)

	require.Equal(t, "dave", user.Username)
	require.Equal(t, []externalGroupMembership{{username: "dave", groupID: "Developers"}}, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
}

func TestProvisionExternalUserGroupFailureLeavesPendingUser(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	addErr := errors.New("add group failed")
	authService.addUserToGroupErr = addErr

	user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
		ExternalID: "erin",
		Source:     "oidc",
	}, []string{"Developers"}, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, addErr)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Len(t, authService.createRequests, 1)
	require.Equal(t, []externalGroupMembership{{username: "erin", groupID: "Developers"}}, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
	_, getErr := authService.GetUserByExternalID(t.Context(), "erin")
	require.NoError(t, getErr)
}

func TestProvisionExternalUserRetryRepairsStoredInitialGroups(t *testing.T) {
	authService := newExternalIdentityAuthService()
	addErr := errors.New("add group failed")
	authService.addUserToGroupErr = addErr
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{
		ExternalID: "frank",
		Source:     "oidc",
	}

	user, err := resolveOrProvisionForTest(t, provisioner, identity, []string{"Original"}, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, addErr)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Empty(t, authService.deletedUsers)

	record, _, err := provisioner.store.Get(t.Context(), identity)
	require.NoError(t, err)
	require.Empty(t, record.OwnerToken)

	authService.addUserToGroupErr = nil
	calledGroupLoader := false
	user, err = provisioner.ResolveOrProvisionExternalUser(t.Context(), identity, func() ([]string, error) {
		calledGroupLoader = true
		return []string{"Changed"}, nil
	}, ExternalIdentityProvisioningOptions{})
	require.NoError(t, err)
	require.Equal(t, "frank", user.Username)
	require.False(t, calledGroupLoader)
	require.Equal(t, []externalGroupMembership{
		{username: "frank", groupID: "Original"},
		{username: "frank", groupID: "Original"},
	}, authService.addedGroups)
}

func TestResolveOrProvisionExternalUserBlocksConcurrentPendingAfterLookupMiss(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "grace", Source: "oidc"}
	firstLookupDone := make(chan struct{})
	releaseFirstLookup := make(chan struct{})
	pendingUserCreated := make(chan struct{})
	releaseGroupAdd := make(chan struct{})

	var firstLookupOnce sync.Once
	authService.afterGetUserByExternalID = func(externalID string, call int) {
		if externalID == identity.ExternalID && call == 1 {
			firstLookupOnce.Do(func() {
				close(firstLookupDone)
				<-releaseFirstLookup
			})
		}
	}
	var groupAddOnce sync.Once
	authService.beforeAddUserToGroup = func(username, _ string, call int) {
		if username == identity.ExternalID && call == 1 {
			groupAddOnce.Do(func() {
				close(pendingUserCreated)
				<-releaseGroupAdd
			})
		}
	}

	firstResult := make(chan error, 1)
	firstGroupLoaderCalled := false
	go func() {
		_, err := provisioner.ResolveOrProvisionExternalUser(t.Context(), identity, func() ([]string, error) {
			firstGroupLoaderCalled = true
			return []string{"First"}, nil
		}, ExternalIdentityProvisioningOptions{})
		firstResult <- err
	}()
	waitForTestSignal(t, firstLookupDone)

	secondResult := make(chan error, 1)
	go func() {
		_, err := resolveOrProvisionForTest(t, provisioner, identity, []string{"Second"}, ExternalIdentityProvisioningOptions{})
		secondResult <- err
	}()
	waitForTestSignal(t, pendingUserCreated)

	close(releaseFirstLookup)
	err := waitForTestResult(t, firstResult)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.False(t, firstGroupLoaderCalled)

	close(releaseGroupAdd)
	require.NoError(t, waitForTestResult(t, secondResult))
	require.Equal(t, []externalGroupMembership{{username: "grace", groupID: "Second"}}, authService.addedGroups)
}

func TestResolveOrProvisionExternalUserRefetchesCompletedRaceAfterLookupMiss(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "mona", Source: "oidc", FriendlyName: "Mona"}
	var hookErr error
	var completeRaceOnce sync.Once
	authService.afterGetUserByExternalID = func(externalID string, call int) {
		if externalID != identity.ExternalID || call != 1 {
			return
		}
		completeRaceOnce.Do(func() {
			authService.mu.Lock()
			authService.usersByExternalID[identity.ExternalID] = &model.User{
				Username:   "mona",
				ExternalID: stringPtr(identity.ExternalID),
				Source:     identity.Source,
			}
			authService.mu.Unlock()

			now := time.Now()
			hookErr = provisioner.store.SetIf(t.Context(), identity, &externalIdentityProvisioningRecord{
				State:          externalIdentityProvisioningComplete,
				Username:       "mona",
				Source:         identity.Source,
				ExternalIDHash: externalIdentityProvisioningHash(identity),
				InitialGroups:  []string{"Race"},
				Generation:     1,
				CreatedAt:      now,
				UpdatedAt:      now,
			}, nil)
		})
	}
	calledGroupLoader := false

	user, err := provisioner.ResolveOrProvisionExternalUser(t.Context(), identity, func() ([]string, error) {
		calledGroupLoader = true
		return []string{"Current"}, nil
	}, ExternalIdentityProvisioningOptions{})
	require.NoError(t, hookErr)
	require.NoError(t, err)
	require.Equal(t, "mona", user.Username)
	require.False(t, calledGroupLoader)
	require.Empty(t, authService.createRequests)
	require.Empty(t, authService.addedGroups)
}

func TestPendingProvisioningBlocksAuthentication(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "gina", Source: "oidc"}
	_, acquired, err := provisioner.createPending(t.Context(), identity, []string{"Developers"})
	require.NoError(t, err)
	require.True(t, acquired)

	user, found, err := provisioner.ResolveExternalUser(t.Context(), identity, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.False(t, found)
	require.Empty(t, authService.createRequests)
}

func TestOldProvisioningOwnerCannotCompleteAfterTakeover(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "henry", Source: "oidc"}
	lease, acquired, err := provisioner.createPending(t.Context(), identity, []string{"Developers"})
	require.NoError(t, err)
	require.True(t, acquired)
	lease.record.UpdatedAt = time.Now().Add(-externalIdentityProvisioningLeaseTTL - time.Minute)
	require.NoError(t, provisioner.store.SetIf(t.Context(), identity, lease.record, lease.predicate))

	staleRecord, stalePredicate, err := provisioner.store.Get(t.Context(), identity)
	require.NoError(t, err)
	nextLease, acquired, err := provisioner.claimPending(t.Context(), identity, staleRecord, stalePredicate)
	require.NoError(t, err)
	require.True(t, acquired)
	require.Equal(t, []string{"Developers"}, nextLease.record.InitialGroups)

	_, err = provisioner.completeLease(t.Context(), identity, lease)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
}

func TestCompletedProvisioningMarkerWithMissingUserReprovisions(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "irene", Source: "oidc"}

	user, err := resolveOrProvisionForTest(t, provisioner, identity, []string{"Original"}, ExternalIdentityProvisioningOptions{})
	require.NoError(t, err)
	require.Equal(t, "irene", user.Username)
	require.NoError(t, authService.DeleteUser(t.Context(), "irene"))

	reloadedGroups := false
	user, err = provisioner.ResolveOrProvisionExternalUser(t.Context(), identity, func() ([]string, error) {
		reloadedGroups = true
		return []string{"Current"}, nil
	}, ExternalIdentityProvisioningOptions{})
	require.NoError(t, err)
	require.True(t, reloadedGroups)
	require.Equal(t, "irene", user.Username)
	require.Len(t, authService.createRequests, 2)
	require.Equal(t, []externalGroupMembership{
		{username: "irene", groupID: "Original"},
		{username: "irene", groupID: "Current"},
	}, authService.addedGroups)
}

func TestResolveExternalUserInvalidMarkerStateFailsClosedWithoutFriendlyNameUpdate(t *testing.T) {
	authService := newExternalIdentityAuthService(&model.User{
		Username:     "jill",
		ExternalID:   stringPtr("jill"),
		Source:       "oidc",
		FriendlyName: stringPtr("Old Name"),
	})
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "jill", Source: "oidc", FriendlyName: "New Name"}
	require.NoError(t, provisioner.store.SetIf(t.Context(), identity, &externalIdentityProvisioningRecord{
		State:          "unknown",
		Username:       "jill",
		Source:         "oidc",
		ExternalIDHash: externalIdentityProvisioningHash(identity),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}, nil))

	user, found, err := provisioner.ResolveExternalUser(t.Context(), identity, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.False(t, found)
	require.Nil(t, user)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestResolveExternalUserMarkerUsernameMismatchFailsClosedWithoutFriendlyNameUpdate(t *testing.T) {
	authService := newExternalIdentityAuthService(&model.User{
		Username:     "jill",
		ExternalID:   stringPtr("jill"),
		Source:       "oidc",
		FriendlyName: stringPtr("Old Name"),
	})
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "jill", Source: "oidc", FriendlyName: "New Name"}
	require.NoError(t, provisioner.store.SetIf(t.Context(), identity, &externalIdentityProvisioningRecord{
		State:          externalIdentityProvisioningComplete,
		Username:       "other-user",
		Source:         "oidc",
		ExternalIDHash: externalIdentityProvisioningHash(identity),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}, nil))

	user, found, err := provisioner.ResolveExternalUser(t.Context(), identity, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.False(t, found)
	require.Nil(t, user)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestResolveExternalUserCorruptMarkerWrapsInternalServerError(t *testing.T) {
	ctx := t.Context()
	kvStore := kvtest.GetStore(ctx, t)
	authService := newExternalIdentityAuthService(&model.User{
		Username:   "kate",
		ExternalID: stringPtr("kate"),
		Source:     "oidc",
	})
	provisioner := NewExternalIdentityProvisioner(authService, kvStore, logging.ContextUnavailable())
	identity := ExternalIdentity{ExternalID: "kate", Source: "oidc", FriendlyName: "New Name"}
	require.NoError(t, kvStore.Set(ctx, []byte(model.PartitionKey), externalIdentityProvisioningKey(identity), []byte("{")))

	user, found, err := provisioner.ResolveExternalUser(ctx, identity, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.ErrorIs(t, err, ErrInternalServerError)
	require.False(t, found)
	require.Nil(t, user)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestExternalIdentityProvisioningInfrastructureFailuresWrapInternalServerError(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*ExternalIdentityProvisioner)
		resolve    bool
		wantCreate bool
	}{
		{
			name: "store get failure",
			configure: func(p *ExternalIdentityProvisioner) {
				p.store = &failingExternalIdentityProvisioningStore{getErr: errors.New("kv down")}
			},
			resolve: true,
		},
		{
			name: "store set failure",
			configure: func(p *ExternalIdentityProvisioner) {
				p.store = &failingExternalIdentityProvisioningStore{setErr: errors.New("kv down")}
			},
		},
		{
			name: "owner token failure",
			configure: func(p *ExternalIdentityProvisioner) {
				p.ownerToken = func() (string, error) {
					return "", errors.New("random down")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := newExternalIdentityAuthService()
			provisioner := newExternalIdentityProvisionerForTest(t, authService)
			tt.configure(provisioner)
			identity := ExternalIdentity{ExternalID: "louis", Source: "oidc"}

			if tt.resolve {
				user, found, err := provisioner.ResolveExternalUser(t.Context(), identity, ExternalIdentityProvisioningOptions{})
				require.ErrorIs(t, err, ErrInternalServerError)
				require.False(t, found)
				require.Nil(t, user)
			} else {
				user, err := resolveOrProvisionForTest(t, provisioner, identity, []string{"Developers"}, ExternalIdentityProvisioningOptions{})
				require.ErrorIs(t, err, ErrInternalServerError)
				require.Nil(t, user)
			}
			require.Empty(t, authService.createRequests)
		})
	}
}

func TestResolveExternalUserLookupFailureWrapsInternalServerError(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	lookupErr := errors.New("lookup storage unavailable")
	authService.getUserByExternalErr = lookupErr

	user, found, err := provisioner.ResolveExternalUser(t.Context(), ExternalIdentity{
		ExternalID: "mike",
		Source:     "oidc",
	}, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, lookupErr)
	require.ErrorIs(t, err, ErrInternalServerError)
	require.False(t, found)
	require.Nil(t, user)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestResolveExternalUserInvalidIdentityDoesNotMutate(t *testing.T) {
	tests := []struct {
		name     string
		identity ExternalIdentity
	}{
		{
			name: "empty external id",
			identity: ExternalIdentity{
				Source: "oidc",
			},
		},
		{
			name: "empty source",
			identity: ExternalIdentity{
				ExternalID: "grace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := newExternalIdentityAuthService()
			provisioner := newExternalIdentityProvisionerForTest(t, authService)

			user, found, err := provisioner.ResolveExternalUser(t.Context(), tt.identity, ExternalIdentityProvisioningOptions{})
			require.ErrorIs(t, err, ErrAuthenticatingRequest)
			require.False(t, found)
			require.Nil(t, user)
			require.Empty(t, authService.createRequests)
			require.Empty(t, authService.addedGroups)
			require.Empty(t, authService.deletedUsers)
			require.Empty(t, authService.friendlyNameUpdates)
		})
	}
}

type failingExternalIdentityProvisioningStore struct {
	getErr error
	setErr error
}

func (s *failingExternalIdentityProvisioningStore) Get(_ context.Context, _ ExternalIdentity) (*externalIdentityProvisioningRecord, kv.Predicate, error) {
	if s.getErr != nil {
		return nil, nil, s.getErr
	}
	return nil, nil, kv.ErrNotFound
}

func (s *failingExternalIdentityProvisioningStore) SetIf(_ context.Context, _ ExternalIdentity, _ *externalIdentityProvisioningRecord, _ kv.Predicate) error {
	if s.setErr != nil {
		return s.setErr
	}
	return nil
}

func waitForTestSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for test signal")
	}
}

func waitForTestResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for test result")
		return nil
	}
}

func TestProvisionExternalUserInvalidGroupsDoesNotMutate(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
	}{
		{name: "empty group", groups: []string{"Developers", ""}},
		{name: "whitespace group", groups: []string{" \t"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := newExternalIdentityAuthService()
			provisioner := newExternalIdentityProvisionerForTest(t, authService)

			user, err := resolveOrProvisionForTest(t, provisioner, ExternalIdentity{
				ExternalID: "heidi",
				Source:     "oidc",
			}, tt.groups, ExternalIdentityProvisioningOptions{})
			require.ErrorIs(t, err, ErrAuthenticatingRequest)
			require.Nil(t, user)
			require.Empty(t, authService.createRequests)
			require.Empty(t, authService.addedGroups)
			require.Empty(t, authService.deletedUsers)
			require.Empty(t, authService.friendlyNameUpdates)
		})
	}
}
