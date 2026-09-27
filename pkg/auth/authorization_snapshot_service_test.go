package auth_test

import (
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/contrib/auth/acl"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/model"
	authparams "github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func TestPreparedAuthorizationAPIServiceRetrievesPoliciesOnce(t *testing.T) {
	t.Parallel()
	client, service := NewTestApiService(t, false)
	client.EXPECT().ListUserPoliciesWithResponse(gomock.Any(), "alice", gomock.Any()).Return(&auth.ListUserPoliciesResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		JSON200:      &auth.PolicyList{Results: []auth.Policy{{Statement: []auth.Statement{{Effect: "allow", Action: []string{permissions.ReadObjectAction}, Resource: "*"}}}}},
	}, nil).Times(1)
	prepared, err := auth.PrepareAuthorization(t.Context(), service, "alice")
	require.NoError(t, err)
	node := permissions.Node{Permission: permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "document")}}
	require.True(t, prepared.CanAuthorize(node))
	response, err := prepared.Authorize(t.Context(), &auth.AuthorizationRequest{Username: "alice", RequiredPermissions: node})
	require.NoError(t, err)
	require.True(t, response.Allowed)
}

func TestPreparedAuthorizationBasicAuthFallback(t *testing.T) {
	t.Parallel()
	service, _ := SetupService(t, "secret")
	_, err := service.CreateUser(t.Context(), &model.User{Username: "admin"})
	require.NoError(t, err)
	node := permissions.Node{Permission: permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "document")}}
	for _, username := range []string{"admin", "unknown"} {
		t.Run(username, func(t *testing.T) {
			prepared, err := auth.PrepareAuthorization(t.Context(), service, username)
			require.NoError(t, err)
			require.True(t, prepared.CanAuthorize(node), "unsupported policy listing must not reject a BasicAuth user")
			response, err := prepared.Authorize(t.Context(), &auth.AuthorizationRequest{Username: username, RequiredPermissions: node})
			if username == "admin" {
				require.NoError(t, err)
				require.True(t, response.Allowed)
			} else {
				require.Error(t, err, "the original authorizer still validates the user")
				require.Nil(t, response)
			}
		})
	}
}

func TestPreparedAuthorizationLocalACLUsesSamePolicySnapshot(t *testing.T) {
	t.Parallel()
	store := kvtest.GetStore(t.Context(), t)
	service := acl.NewAuthService(store, crypt.NewSecretStore([]byte("secret")), authparams.ServiceCache{Enabled: false}, true)
	_, err := service.CreateUser(t.Context(), &model.User{Username: "alice"})
	require.NoError(t, err)
	policy := &model.Policy{DisplayName: "read-object", Statement: model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*"}}}
	require.NoError(t, service.WritePolicy(t.Context(), policy, false))
	require.NoError(t, service.AttachPolicyToUser(t.Context(), policy.DisplayName, "alice"))
	prepared, err := auth.PrepareAuthorization(t.Context(), service, "alice")
	require.NoError(t, err)

	// A later request sees the changed policy; this prepared request keeps its existing snapshot.
	require.NoError(t, service.DetachPolicyFromUser(t.Context(), policy.DisplayName, "alice"))
	req := &auth.AuthorizationRequest{Username: "alice", RequiredPermissions: permissions.Node{Permission: permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "document")}}}
	response, err := service.Authorize(t.Context(), req)
	require.NoError(t, err)
	require.False(t, response.Allowed)
	response, err = prepared.Authorize(t.Context(), req)
	require.NoError(t, err)
	require.True(t, response.Allowed)
}
