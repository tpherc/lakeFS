package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	oidcencoding "github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestOIDCClaimsFromSessionDecodesJSONClaims(t *testing.T) {
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"alice","groups":["Developers","Viewers"],"nested":{"role":"admin"}}`,
	}}
	MarkOIDCSessionClaimsCurrent(session)

	claims, found, err := oidcClaimsFromSession(session)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "alice", claims["sub"])
	require.Equal(t, []any{"Developers", "Viewers"}, claims["groups"])
	require.Equal(t, map[string]any{"role": "admin"}, claims["nested"])
}

func TestOIDCClaimsFromSessionRejectsHistoricalClaimsValue(t *testing.T) {
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: oidcencoding.Claims{"sub": "alice"},
	}}

	claims, found, err := oidcClaimsFromSession(session)
	require.Error(t, err)
	require.True(t, found)
	require.Nil(t, claims)
}

func TestOIDCClaimsFromSessionRejectsJSONClaimsWithoutCurrentSchema(t *testing.T) {
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"alice"}`,
	}}

	claims, found, err := oidcClaimsFromSession(session)
	require.Error(t, err)
	require.True(t, found)
	require.Nil(t, claims)
}

func TestInitialGroupsFromClaims(t *testing.T) {
	tests := []struct {
		name          string
		claim         any
		defaultGroups []string
		want          []string
		wantErr       error
	}{
		{
			name:          "nil uses defaults",
			defaultGroups: []string{"Developers"},
			want:          []string{"Developers"},
		},
		{
			name:  "comma separated string trims filters and deduplicates",
			claim: "Developers, Viewers, Developers, , Admins ",
			want:  []string{"Developers", "Viewers", "Admins"},
		},
		{
			name:  "string array trims filters and deduplicates",
			claim: []string{"Developers", " ", "Viewers", "Developers"},
			want:  []string{"Developers", "Viewers"},
		},
		{
			name:  "any array trims filters and deduplicates",
			claim: []any{"Developers", " ", "Viewers", "Developers"},
			want:  []string{"Developers", "Viewers"},
		},
		{
			name:    "any array rejects non string item",
			claim:   []any{"Developers", 3},
			wantErr: ErrInvalidFormat,
		},
		{
			name:    "unsupported claim type fails closed",
			claim:   map[string]any{"group": "Developers"},
			wantErr: ErrInvalidFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := initialGroupsFromClaims(tt.claim, tt.defaultGroups)
			if tt.wantErr != nil {
				require.True(t, errors.Is(err, tt.wantErr), "got err %v", err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

type oidcSessionAuthService struct {
	Service
	usersByExternalID map[string]*model.User

	createdUsers         []*model.User
	addedGroups          []oidcGroupMembership
	friendlyNameUpdates  []friendlyNameUpdate
	deletedUsers         []string
	getUserByExternalErr error
	createUserErr        error
	addUserToGroupErr    error
}

type oidcGroupMembership struct {
	username string
	groupID  string
}

type friendlyNameUpdate struct {
	username     string
	friendlyName string
}

func newOIDCSessionAuthService(users ...*model.User) *oidcSessionAuthService {
	s := &oidcSessionAuthService{usersByExternalID: make(map[string]*model.User)}
	for _, user := range users {
		if user.ExternalID != nil {
			s.usersByExternalID[*user.ExternalID] = cloneUser(user)
		}
	}
	return s
}

func (s *oidcSessionAuthService) GetUserByExternalID(_ context.Context, externalID string) (*model.User, error) {
	if s.getUserByExternalErr != nil {
		return nil, s.getUserByExternalErr
	}
	user := s.usersByExternalID[externalID]
	if user == nil {
		return nil, ErrNotFound
	}
	return cloneUser(user), nil
}

func (s *oidcSessionAuthService) CreateUser(_ context.Context, user *model.User) (string, error) {
	if s.createUserErr != nil {
		return "", s.createUserErr
	}
	copied := cloneUser(user)
	s.createdUsers = append(s.createdUsers, copied)
	if copied.ExternalID != nil {
		s.usersByExternalID[*copied.ExternalID] = cloneUser(copied)
	}
	return user.Username, nil
}

func (s *oidcSessionAuthService) AddUserToGroup(_ context.Context, username, groupID string) error {
	s.addedGroups = append(s.addedGroups, oidcGroupMembership{username: username, groupID: groupID})
	if s.addUserToGroupErr != nil {
		return s.addUserToGroupErr
	}
	return nil
}

func (s *oidcSessionAuthService) DeleteUser(_ context.Context, username string) error {
	s.deletedUsers = append(s.deletedUsers, username)
	for externalID, user := range s.usersByExternalID {
		if user.Username == username {
			delete(s.usersByExternalID, externalID)
		}
	}
	return nil
}

func (s *oidcSessionAuthService) UpdateUserFriendlyName(_ context.Context, username, friendlyName string) error {
	s.friendlyNameUpdates = append(s.friendlyNameUpdates, friendlyNameUpdate{
		username:     username,
		friendlyName: friendlyName,
	})
	return nil
}

func TestUserFromOIDCSessionCreatesUserAndAssignsInitialGroups(t *testing.T) {
	authService := newOIDCSessionAuthService()
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{
			"iss": "https://issuer.example",
			"sub": "alice",
			"name": "Alice Example",
			"email": "alice@example.com",
			"department": "Data",
			"roles": "Developers, Viewers, Developers"
		}`,
	}}
	MarkOIDCSessionClaimsCurrent(session)

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), authService, session, &OIDCConfig{
		ValidateIDTokenClaims:  map[string]string{"department": "Data"},
		DefaultInitialGroups:   []string{"Admins"},
		InitialGroupsClaimName: "roles",
		FriendlyNameClaimName:  "name",
		EmailClaimName:         "email",
		PersistFriendlyName:    true,
	})
	require.NoError(t, err)

	require.Equal(t, "alice", user.Username)
	require.Equal(t, "oidc", user.Source)
	require.Equal(t, "alice", stringValue(user.ExternalID))
	require.Equal(t, "Alice Example", stringValue(user.FriendlyName))
	require.Equal(t, "alice@example.com", stringValue(user.Email))

	require.Len(t, authService.createdUsers, 1)
	created := authService.createdUsers[0]
	require.Equal(t, "alice", created.Username)
	require.Equal(t, "oidc", created.Source)
	require.Equal(t, "alice", stringValue(created.ExternalID))
	require.Equal(t, "Alice Example", stringValue(created.FriendlyName))
	require.Equal(t, "alice@example.com", stringValue(created.Email))
	require.Equal(t, []oidcGroupMembership{
		{username: "alice", groupID: "Developers"},
		{username: "alice", groupID: "Viewers"},
	}, authService.addedGroups)
}

func TestUserFromOIDCSessionExistingUserUpdatesFriendlyNameWithoutInitialGroupChanges(t *testing.T) {
	authService := newOIDCSessionAuthService(&model.User{
		Username:     "bob",
		ExternalID:   stringPtr("bob"),
		FriendlyName: stringPtr("Old Name"),
		Source:       "oidc",
	})
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{
			"sub": "bob",
			"name": "Bob New",
			"roles": "Admins"
		}`,
	}}
	MarkOIDCSessionClaimsCurrent(session)

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), authService, session, &OIDCConfig{
		DefaultInitialGroups:   []string{"Developers"},
		InitialGroupsClaimName: "roles",
		FriendlyNameClaimName:  "name",
		PersistFriendlyName:    true,
	})
	require.NoError(t, err)

	require.Equal(t, "bob", user.Username)
	require.Equal(t, "Bob New", stringValue(user.FriendlyName))
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
	require.Equal(t, []friendlyNameUpdate{{username: "bob", friendlyName: "Bob New"}}, authService.friendlyNameUpdates)
}

func TestUserFromOIDCSessionRequiredClaimMismatchDoesNotMutateUsers(t *testing.T) {
	authService := newOIDCSessionAuthService()
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"carol","department":"Finance"}`,
	}}
	MarkOIDCSessionClaimsCurrent(session)

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), authService, session, &OIDCConfig{
		ValidateIDTokenClaims: map[string]string{"department": "Data"},
	})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.Nil(t, user)
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
}

func TestUserFromOIDCSessionValidatesInitialGroupsBeforeCreate(t *testing.T) {
	authService := newOIDCSessionAuthService()
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"dave","roles":["Developers",7]}`,
	}}
	MarkOIDCSessionClaimsCurrent(session)

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), authService, session, &OIDCConfig{
		InitialGroupsClaimName: "roles",
	})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.Nil(t, user)
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
}

func TestUserFromOIDCSessionRollsBackUserAfterInitialGroupFailure(t *testing.T) {
	authService := newOIDCSessionAuthService()
	authService.addUserToGroupErr = ErrInternalServerError
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"erin","roles":["Developers"]}`,
	}}
	MarkOIDCSessionClaimsCurrent(session)

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), authService, session, &OIDCConfig{
		InitialGroupsClaimName: "roles",
	})
	require.ErrorIs(t, err, ErrInternalServerError)
	require.Nil(t, user)
	require.Len(t, authService.createdUsers, 1)
	require.Equal(t, []oidcGroupMembership{{username: "erin", groupID: "Developers"}}, authService.addedGroups)
	require.Equal(t, []string{"erin"}, authService.deletedUsers)
	_, getErr := authService.GetUserByExternalID(t.Context(), "erin")
	require.ErrorIs(t, getErr, ErrNotFound)
}

func cloneUser(user *model.User) *model.User {
	if user == nil {
		return nil
	}
	copied := *user
	return &copied
}

func stringPtr(value string) *string {
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
