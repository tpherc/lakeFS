package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
)

type externalIdentityAuthService struct {
	Service
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
	s.getUserCalls++
	if s.getUserByExternalErr != nil {
		return nil, s.getUserByExternalErr
	}
	user := s.usersByExternalID[externalID]
	if user == nil {
		return nil, ErrNotFound
	}
	return cloneUser(user), nil
}

func (s *externalIdentityAuthService) CreateUser(_ context.Context, user *model.User) (string, error) {
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
	s.addedGroups = append(s.addedGroups, externalGroupMembership{username: username, groupID: groupID})
	return s.addUserToGroupErr
}

func (s *externalIdentityAuthService) DeleteUser(_ context.Context, username string) error {
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

	record, predicate, err := provisioner.store.Get(t.Context(), identity)
	require.NoError(t, err)
	record.UpdatedAt = time.Now().Add(-externalIdentityProvisioningLeaseTTL - time.Minute)
	require.NoError(t, provisioner.store.SetIf(t.Context(), identity, record, predicate))

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

func TestPendingProvisioningBlocksAuthentication(t *testing.T) {
	authService := newExternalIdentityAuthService()
	provisioner := newExternalIdentityProvisionerForTest(t, authService)
	identity := ExternalIdentity{ExternalID: "gina", Source: "oidc"}
	_, err := provisioner.acquirePending(t.Context(), identity, []string{"Developers"})
	require.NoError(t, err)

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
	lease, err := provisioner.acquirePending(t.Context(), identity, []string{"Developers"})
	require.NoError(t, err)
	lease.record.UpdatedAt = time.Now().Add(-externalIdentityProvisioningLeaseTTL - time.Minute)
	require.NoError(t, provisioner.store.SetIf(t.Context(), identity, lease.record, lease.predicate))

	staleRecord, stalePredicate, err := provisioner.store.Get(t.Context(), identity)
	require.NoError(t, err)
	_, err = provisioner.takeOverStalePending(t.Context(), identity, staleRecord, stalePredicate)
	require.NoError(t, err)

	_, err = provisioner.completeLease(t.Context(), identity, lease)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
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
