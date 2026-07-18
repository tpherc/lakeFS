package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
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

func TestResolveOrProvisionExternalUserCreatesUserAndAssignsInitialGroups(t *testing.T) {
	authService := newExternalIdentityAuthService()

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:    "alice",
		Source:        "oidc",
		FriendlyName:  "Alice Example",
		Email:         "alice@example.com",
		InitialGroups: []string{"Developers", "Viewers"},
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
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

func TestResolveOrProvisionExternalUserExistingUserUpdatesFriendlyNameOnly(t *testing.T) {
	authService := newExternalIdentityAuthService(&model.User{
		Username:     "bob",
		ExternalID:   stringPtr("bob"),
		Source:       "oidc",
		FriendlyName: stringPtr("Old Name"),
		Email:        stringPtr("old@example.com"),
	})

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:    "bob",
		Source:        "oidc",
		FriendlyName:  "Bob New",
		Email:         "new@example.com",
		InitialGroups: []string{"Admins"},
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.NoError(t, err)

	require.Equal(t, "bob", user.Username)
	require.Equal(t, "Bob New", stringValue(user.FriendlyName))
	require.Equal(t, "old@example.com", stringValue(user.Email))
	require.Empty(t, authService.createRequests)
	require.Empty(t, authService.addedGroups)
	require.Equal(t, []externalFriendlyNameUpdate{{username: "bob", friendlyName: "Bob New"}}, authService.friendlyNameUpdates)
}

func TestResolveOrProvisionExternalUserFindsLegacyExternalID(t *testing.T) {
	authService := newExternalIdentityAuthService(&model.User{
		Username:     "legacy-alice",
		ExternalID:   stringPtr("alice"),
		Source:       "oidc",
		FriendlyName: stringPtr("Old Name"),
	})

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:        "oidc:hashed-alice",
		LegacyExternalIDs: []string{"alice"},
		Source:            "oidc",
		FriendlyName:      "Alice New",
		InitialGroups:     []string{"Developers"},
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.NoError(t, err)

	require.Equal(t, "legacy-alice", user.Username)
	require.Equal(t, "Alice New", stringValue(user.FriendlyName))
	require.Equal(t, 2, authService.getUserCalls)
	require.Empty(t, authService.createRequests)
	require.Empty(t, authService.addedGroups)
	require.Equal(t, []externalFriendlyNameUpdate{{username: "legacy-alice", friendlyName: "Alice New"}}, authService.friendlyNameUpdates)
}

func TestResolveOrProvisionExternalUserReturnsFriendlyNameWithoutPersisting(t *testing.T) {
	authService := newExternalIdentityAuthService()

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:   "brenda",
		Source:       "oidc",
		FriendlyName: "Brenda Viewer",
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: false})
	require.NoError(t, err)

	require.Equal(t, "Brenda Viewer", stringValue(user.FriendlyName))
	require.Len(t, authService.createRequests, 1)
	require.Empty(t, stringValue(authService.createRequests[0].FriendlyName))
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestResolveOrProvisionExternalUserCreateRaceFetchesWinner(t *testing.T) {
	authService := newExternalIdentityAuthService()
	authService.createUserErr = ErrAlreadyExists
	authService.createRaceWinner = &model.User{
		Username:     "race-winner",
		ExternalID:   stringPtr("carol"),
		Source:       "oidc",
		FriendlyName: stringPtr("Carol Winner"),
	}

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:    "carol",
		Source:        "oidc",
		FriendlyName:  "Carol Winner",
		InitialGroups: []string{"Developers"},
	}, ExternalIdentityProvisioningOptions{PersistFriendlyName: true})
	require.NoError(t, err)

	require.Equal(t, "race-winner", user.Username)
	require.Len(t, authService.createRequests, 1)
	require.Empty(t, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
}

func TestResolveOrProvisionExternalUserGroupAlreadyExistsIsSuccess(t *testing.T) {
	authService := newExternalIdentityAuthService()
	authService.addUserToGroupErr = ErrAlreadyExists

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:    "dave",
		Source:        "oidc",
		InitialGroups: []string{"Developers"},
	}, ExternalIdentityProvisioningOptions{})
	require.NoError(t, err)

	require.Equal(t, "dave", user.Username)
	require.Equal(t, []externalGroupMembership{{username: "dave", groupID: "Developers"}}, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
}

func TestResolveOrProvisionExternalUserGroupFailureRollsBackUser(t *testing.T) {
	authService := newExternalIdentityAuthService()
	addErr := errors.New("add group failed")
	authService.addUserToGroupErr = addErr

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:    "erin",
		Source:        "oidc",
		InitialGroups: []string{"Developers"},
	}, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, addErr)
	require.Nil(t, user)
	require.Len(t, authService.createRequests, 1)
	require.Equal(t, []externalGroupMembership{{username: "erin", groupID: "Developers"}}, authService.addedGroups)
	require.Equal(t, []string{"erin"}, authService.deletedUsers)
	_, getErr := authService.GetUserByExternalID(t.Context(), "erin")
	require.ErrorIs(t, getErr, ErrNotFound)
}

func TestResolveOrProvisionExternalUserRollbackFailureReturnsBothErrors(t *testing.T) {
	authService := newExternalIdentityAuthService()
	addErr := errors.New("add group failed")
	deleteErr := errors.New("delete user failed")
	authService.addUserToGroupErr = addErr
	authService.deleteUserErr = deleteErr

	user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, ExternalIdentity{
		ExternalID:    "frank",
		Source:        "oidc",
		InitialGroups: []string{"Developers"},
	}, ExternalIdentityProvisioningOptions{})
	require.ErrorIs(t, err, addErr)
	require.ErrorIs(t, err, deleteErr)
	require.Nil(t, user)
	require.Equal(t, []string{"frank"}, authService.deletedUsers)
	_, getErr := authService.GetUserByExternalID(t.Context(), "frank")
	require.NoError(t, getErr)
}

func TestResolveOrProvisionExternalUserInvalidIdentityDoesNotMutate(t *testing.T) {
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
		{
			name: "empty group",
			identity: ExternalIdentity{
				ExternalID:    "heidi",
				Source:        "oidc",
				InitialGroups: []string{"Developers", ""},
			},
		},
		{
			name: "whitespace group",
			identity: ExternalIdentity{
				ExternalID:    "ivan",
				Source:        "oidc",
				InitialGroups: []string{" \t"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := newExternalIdentityAuthService()

			user, err := ResolveOrProvisionExternalUser(t.Context(), logging.ContextUnavailable(), authService, tt.identity, ExternalIdentityProvisioningOptions{})
			require.ErrorIs(t, err, ErrAuthenticatingRequest)
			require.Nil(t, user)
			require.Empty(t, authService.createRequests)
			require.Empty(t, authService.addedGroups)
			require.Empty(t, authService.deletedUsers)
			require.Empty(t, authService.friendlyNameUpdates)
		})
	}
}
