package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	oidcencoding "github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestOIDCClaimsFromSessionDecodesJSONClaims(t *testing.T) {
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"alice","groups":["Developers","Viewers"],"nested":{"role":"admin"}}`,
	}}
	MarkOIDCSessionClaimsCurrent(session, time.Now().Add(time.Hour))

	claims, found, err := oidcClaimsFromSession(session, time.Now())
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

	claims, found, err := oidcClaimsFromSession(session, time.Now())
	require.Error(t, err)
	require.True(t, found)
	require.Nil(t, claims)
}

func TestOIDCClaimsFromSessionRejectsJSONClaimsWithoutCurrentSchema(t *testing.T) {
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"alice"}`,
	}}

	claims, found, err := oidcClaimsFromSession(session, time.Now())
	require.Error(t, err)
	require.True(t, found)
	require.Nil(t, claims)
}

func TestOIDCClaimsFromSessionRejectsExpiredSession(t *testing.T) {
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"sub":"alice"}`,
	}}
	MarkOIDCSessionClaimsCurrent(session, time.Now().Add(-time.Second))

	claims, found, err := oidcClaimsFromSession(session, time.Now())
	require.ErrorIs(t, err, ErrSessionExpired)
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
			name:          "nil uses normalized defaults",
			defaultGroups: []string{"Developers", " ", "Developers", "Viewers"},
			want:          []string{"Developers", "Viewers"},
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

func newOIDCSessionProvisionerForTest(t *testing.T, authService *oidcSessionAuthService) *ExternalIdentityProvisioner {
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
		if _, ok := s.usersByExternalID[*copied.ExternalID]; ok {
			return "", ErrAlreadyExists
		}
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

func TestResolveOrProvisionOIDCUserFromClaimsCreatesUserAndAssignsInitialGroups(t *testing.T) {
	authService := newOIDCSessionAuthService()
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	externalID := oidcExternalID("https://issuer.example", "alice/opaque")
	user, err := ResolveOrProvisionOIDCUserFromClaims(t.Context(), logging.ContextUnavailable(), provisioner, oidcencoding.Claims{
		"iss":        "https://issuer.example",
		"sub":        "alice/opaque",
		"name":       "Alice Example",
		"email":      "alice@example.com",
		"department": "Data",
		"roles":      "Developers, Viewers, Developers",
	}, &OIDCConfig{
		ValidateIDTokenClaims:  map[string]string{"department": "Data"},
		DefaultInitialGroups:   []string{"Admins"},
		InitialGroupsClaimName: "roles",
		FriendlyNameClaimName:  "name",
		EmailClaimName:         "email",
		PersistFriendlyName:    true,
	})
	require.NoError(t, err)

	require.Equal(t, externalID, user.Username)
	require.Equal(t, "oidc", user.Source)
	require.Equal(t, externalID, stringValue(user.ExternalID))
	require.Equal(t, "Alice Example", stringValue(user.FriendlyName))
	require.Equal(t, "alice@example.com", stringValue(user.Email))

	require.Len(t, authService.createdUsers, 1)
	created := authService.createdUsers[0]
	require.Equal(t, externalID, created.Username)
	require.Equal(t, "oidc", created.Source)
	require.Equal(t, externalID, stringValue(created.ExternalID))
	require.Equal(t, "Alice Example", stringValue(created.FriendlyName))
	require.Equal(t, "alice@example.com", stringValue(created.Email))
	require.Equal(t, []oidcGroupMembership{
		{username: externalID, groupID: "Developers"},
		{username: externalID, groupID: "Viewers"},
	}, authService.addedGroups)
}

func TestUserFromOIDCSessionExistingUserUpdatesFriendlyNameWithoutInitialGroupChanges(t *testing.T) {
	externalID := oidcExternalID("https://issuer.example", "bob")
	authService := newOIDCSessionAuthService(&model.User{
		Username:     "bob",
		ExternalID:   stringPtr(externalID),
		FriendlyName: stringPtr("Old Name"),
		Source:       "oidc",
	})
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{
			"iss": "https://issuer.example",
			"sub": "bob",
			"name": "Bob New",
			"roles": ["Admins", 7]
		}`,
	}}
	MarkOIDCSessionClaimsCurrent(session, time.Now().Add(time.Hour))

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &OIDCConfig{
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

func TestUserFromOIDCSessionDoesNotProvisionOrUseRawSubjectExternalID(t *testing.T) {
	authService := newOIDCSessionAuthService(&model.User{
		Username:     "raw-subject-bob",
		ExternalID:   stringPtr("legacy/bob"),
		FriendlyName: stringPtr("Old Name"),
		Source:       "oidc",
	})
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{
			"iss": "https://issuer.example",
			"sub": "legacy/bob",
			"name": "Bob New",
			"roles": "Admins"
		}`,
	}}
	MarkOIDCSessionClaimsCurrent(session, time.Now().Add(time.Hour))

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &OIDCConfig{
		DefaultInitialGroups:   []string{"Developers"},
		InitialGroupsClaimName: "roles",
		FriendlyNameClaimName:  "name",
		PersistFriendlyName:    true,
	})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.Nil(t, user)

	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestUserFromOIDCSessionPendingProvisioningBlocksAuthentication(t *testing.T) {
	externalID := oidcExternalID("https://issuer.example", "carol")
	authService := newOIDCSessionAuthService(&model.User{
		Username:     "carol",
		ExternalID:   stringPtr(externalID),
		Source:       "oidc",
		FriendlyName: stringPtr("Old Name"),
	})
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	_, acquired, err := provisioner.createPending(t.Context(), ExternalIdentity{
		ExternalID: externalID,
		Source:     "oidc",
	}, []string{"Developers"})
	require.NoError(t, err)
	require.True(t, acquired)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{
			"iss": "https://issuer.example",
			"sub": "carol",
			"name": "Carol New"
		}`,
	}}
	MarkOIDCSessionClaimsCurrent(session, time.Now().Add(time.Hour))

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &OIDCConfig{
		FriendlyNameClaimName: "name",
		PersistFriendlyName:   true,
	})
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestUserFromOIDCSessionRequiredClaimMismatchDoesNotMutateUsers(t *testing.T) {
	authService := newOIDCSessionAuthService()
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		IDTokenClaimsSessionKey: `{"iss":"https://issuer.example","sub":"carol","department":"Finance"}`,
	}}
	MarkOIDCSessionClaimsCurrent(session, time.Now().Add(time.Hour))

	user, err := UserFromOIDCSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &OIDCConfig{
		ValidateIDTokenClaims: map[string]string{"department": "Data"},
	})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.Nil(t, user)
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
}

func TestResolveOrProvisionOIDCUserFromClaimsValidatesInitialGroupsBeforeCreate(t *testing.T) {
	authService := newOIDCSessionAuthService()
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	user, err := ResolveOrProvisionOIDCUserFromClaims(t.Context(), logging.ContextUnavailable(), provisioner, oidcencoding.Claims{
		"iss":   "https://issuer.example",
		"sub":   "dave",
		"roles": []any{"Developers", 7},
	}, &OIDCConfig{
		InitialGroupsClaimName: "roles",
	})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.Nil(t, user)
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
}

func TestResolveOrProvisionOIDCUserFromClaimsLeavesPendingUserAfterInitialGroupFailure(t *testing.T) {
	authService := newOIDCSessionAuthService()
	authService.addUserToGroupErr = ErrInternalServerError
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	externalID := oidcExternalID("https://issuer.example", "erin")
	user, err := ResolveOrProvisionOIDCUserFromClaims(t.Context(), logging.ContextUnavailable(), provisioner, oidcencoding.Claims{
		"iss":   "https://issuer.example",
		"sub":   "erin",
		"roles": []any{"Developers"},
	}, &OIDCConfig{
		InitialGroupsClaimName: "roles",
	})
	require.ErrorIs(t, err, ErrInternalServerError)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Len(t, authService.createdUsers, 1)
	require.Equal(t, []oidcGroupMembership{{username: externalID, groupID: "Developers"}}, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
	_, getErr := authService.GetUserByExternalID(t.Context(), externalID)
	require.NoError(t, getErr)
}

func TestUserFromSAMLSessionUsesFallbackSourceAndAssignsInitialGroups(t *testing.T) {
	authService := newOIDCSessionAuthService()
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		SAMLTokenClaimsSessionKey: oidcencoding.Claims{
			"external_id": "sam-user",
			"name":        "Sam User",
			"roles":       []any{"Developers", "Viewers"},
			"department":  "Data",
		},
	}}

	user, err := UserFromSAMLSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &CookieAuthConfig{
		ValidateIDTokenClaims:   map[string]string{"department": "Data"},
		InitialGroupsClaimName:  "roles",
		FriendlyNameClaimName:   "name",
		ExternalUserIDClaimName: "external_id",
		PersistFriendlyName:     true,
	})
	require.NoError(t, err)

	require.Equal(t, "sam-user", user.Username)
	require.Equal(t, "saml", user.Source)
	require.Equal(t, "sam-user", stringValue(user.ExternalID))
	require.Equal(t, "Sam User", stringValue(user.FriendlyName))

	require.Len(t, authService.createdUsers, 1)
	created := authService.createdUsers[0]
	require.Equal(t, "sam-user", created.Username)
	require.Equal(t, "saml", created.Source)
	require.Equal(t, "Sam User", stringValue(created.FriendlyName))
	require.Equal(t, []oidcGroupMembership{
		{username: "sam-user", groupID: "Developers"},
		{username: "sam-user", groupID: "Viewers"},
	}, authService.addedGroups)
}

func TestUserFromSAMLSessionValidatesInitialGroupsBeforeCreate(t *testing.T) {
	authService := newOIDCSessionAuthService()
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		SAMLTokenClaimsSessionKey: oidcencoding.Claims{
			"external_id": "sam-user",
			"roles":       []any{"Developers", 7},
		},
	}}

	user, err := UserFromSAMLSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &CookieAuthConfig{
		InitialGroupsClaimName:  "roles",
		ExternalUserIDClaimName: "external_id",
	})
	require.ErrorIs(t, err, ErrAuthenticatingRequest)
	require.Nil(t, user)
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
}

func TestUserFromSAMLSessionLeavesPendingUserAfterInitialGroupFailure(t *testing.T) {
	authService := newOIDCSessionAuthService()
	authService.addUserToGroupErr = ErrInternalServerError
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		SAMLTokenClaimsSessionKey: oidcencoding.Claims{
			"external_id": "sam-user",
			"roles":       []any{"Developers"},
		},
	}}

	user, err := UserFromSAMLSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &CookieAuthConfig{
		InitialGroupsClaimName:  "roles",
		ExternalUserIDClaimName: "external_id",
	})
	require.ErrorIs(t, err, ErrInternalServerError)
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Len(t, authService.createdUsers, 1)
	require.Equal(t, []oidcGroupMembership{{username: "sam-user", groupID: "Developers"}}, authService.addedGroups)
	require.Empty(t, authService.deletedUsers)
	_, getErr := authService.GetUserByExternalID(t.Context(), "sam-user")
	require.NoError(t, getErr)
}

func TestUserFromSAMLSessionPendingProvisioningBlocksAuthentication(t *testing.T) {
	authService := newOIDCSessionAuthService(&model.User{
		Username:     "sam-user",
		ExternalID:   stringPtr("sam-user"),
		Source:       "saml",
		FriendlyName: stringPtr("Old Name"),
	})
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	_, acquired, err := provisioner.createPending(t.Context(), ExternalIdentity{
		ExternalID: "sam-user",
		Source:     "saml",
	}, []string{"Developers"})
	require.NoError(t, err)
	require.True(t, acquired)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		SAMLTokenClaimsSessionKey: oidcencoding.Claims{
			"external_id": "sam-user",
			"name":        "Sam New",
			"roles":       []any{"Developers", 7},
		},
	}}

	user, err := UserFromSAMLSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &CookieAuthConfig{
		InitialGroupsClaimName:  "roles",
		FriendlyNameClaimName:   "name",
		ExternalUserIDClaimName: "external_id",
		PersistFriendlyName:     true,
	})
	require.ErrorIs(t, err, ErrExternalUserProvisioningIncomplete)
	require.Nil(t, user)
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
	require.Empty(t, authService.friendlyNameUpdates)
}

func TestUserFromSAMLSessionExistingUserIgnoresMalformedInitialGroupClaim(t *testing.T) {
	authService := newOIDCSessionAuthService(&model.User{
		Username:     "sam-user",
		ExternalID:   stringPtr("sam-user"),
		Source:       "saml",
		FriendlyName: stringPtr("Old Name"),
	})
	provisioner := newOIDCSessionProvisionerForTest(t, authService)
	session := &sessions.Session{Values: map[interface{}]interface{}{
		SAMLTokenClaimsSessionKey: oidcencoding.Claims{
			"external_id": "sam-user",
			"name":        "Sam New",
			"roles":       []any{"Developers", 7},
		},
	}}

	user, err := UserFromSAMLSession(t.Context(), logging.ContextUnavailable(), provisioner, session, &CookieAuthConfig{
		InitialGroupsClaimName:  "roles",
		FriendlyNameClaimName:   "name",
		ExternalUserIDClaimName: "external_id",
		PersistFriendlyName:     true,
	})
	require.NoError(t, err)

	require.Equal(t, "sam-user", user.Username)
	require.Equal(t, "Sam New", stringValue(user.FriendlyName))
	require.Empty(t, authService.createdUsers)
	require.Empty(t, authService.addedGroups)
	require.Equal(t, []friendlyNameUpdate{{username: "sam-user", friendlyName: "Sam New"}}, authService.friendlyNameUpdates)
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
