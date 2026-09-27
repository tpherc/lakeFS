package auth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/contrib/auth/acl"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	authparams "github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func TestPolicyVariableWritesRejectInvalidTemplates(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"condition", "resource", "action", "IP operand"} {
		t.Run(field, func(t *testing.T) {
			statement := model.Statement{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*"}
			switch field {
			case "condition":
				statement.Condition = map[string]map[string][]string{"StringLike": {"aws:PrincipalTag/team": {"${aws:PrincipalTag/team, 'fallback'}"}}}
			case "resource":
				statement.Resource = "arn:lakefs:${aws:PrincipalTag/service}:::repository/repo"
			case "action":
				statement.Action = []string{"fs:${aws:PrincipalTag/action}"}
			case "IP operand":
				statement.Condition = map[string]map[string][]string{"IpAddress": {"SourceIp": {"${aws:PrincipalTag/address}"}}}
			}
			policy := &model.Policy{DisplayName: "invalid-template", Statement: model.Statements{statement}}
			_, apiService := NewTestApiService(t, false)
			localService := acl.NewAuthService(kvtest.GetStore(t.Context(), t), crypt.NewSecretStore([]byte("secret")), authparams.ServiceCache{Enabled: false}, true)
			for name, service := range map[string]auth.Service{"API": apiService, "local": localService} {
				t.Run(name, func(t *testing.T) {
					for _, update := range []bool{false, true} {
						require.ErrorIs(t, service.WritePolicy(t.Context(), policy, update), model.ErrValidationError)
					}
				})
			}
		})
	}
}

func TestAPIPolicyVariablesRoundTripAndAuthorize(t *testing.T) {
	t.Parallel()
	client, service := NewTestApiService(t, false)
	resource := permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*")
	conditions := map[string]map[string][]string{
		"StringEquals": {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}},
	}
	policy := &model.Policy{DisplayName: "tagged-read", Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: resource, Condition: conditions,
	}}}
	var stored auth.Policy
	client.EXPECT().CreatePolicyWithResponse(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, body auth.CreatePolicyJSONRequestBody, _ ...auth.RequestEditorFn) (*auth.CreatePolicyResponse, error) {
			stored = auth.Policy(body)
			require.Equal(t, resource, stored.Statement[0].Resource)
			require.Equal(t, conditions["StringEquals"], stored.Statement[0].Condition.AdditionalProperties["StringEquals"].AdditionalProperties)
			return &auth.CreatePolicyResponse{HTTPResponse: &http.Response{StatusCode: http.StatusCreated}}, nil
		})
	require.NoError(t, service.WritePolicy(t.Context(), policy, false))
	client.EXPECT().ListUserPoliciesWithResponse(gomock.Any(), "alice", gomock.Any()).Return(&auth.ListUserPoliciesResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &auth.PolicyList{Results: []auth.Policy{stored}},
	}, nil).Times(1)
	ctx := auth.WithPrincipalTags(t.Context(), principaltags.Tags{"team": "blue"})
	prepared, err := auth.PrepareAuthorization(ctx, service, "alice")
	require.NoError(t, err)
	for _, team := range []string{"blue", "red"} {
		node := permissions.Node{Permission: permissions.Permission{
			Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "blue/document"), ObjectMetadata: map[string]string{"team": team},
		}}
		require.True(t, prepared.CanAuthorize(node))
		response, err := prepared.Authorize(ctx, &auth.AuthorizationRequest{Username: "alice", RequiredPermissions: node})
		require.NoError(t, err)
		require.Equal(t, team == "blue", response.Allowed)
	}
}

func TestLocalPolicyVariablesPersistAndAuthorizeResourceList(t *testing.T) {
	t.Parallel()
	service := acl.NewAuthService(kvtest.GetStore(t.Context(), t), crypt.NewSecretStore([]byte("secret")), authparams.ServiceCache{Enabled: false}, true)
	_, err := service.CreateUser(t.Context(), &model.User{Username: "alice"})
	require.NoError(t, err)
	policy := &model.Policy{DisplayName: "tagged-read", Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction},
		Resource:  `["arn:lakefs:fs:::repository/repo/object/${aws:PrincipalTag/missing}/*","arn:lakefs:fs:::repository/repo/object/${aws:PrincipalTag/team}/*"]`,
		Condition: map[string]map[string][]string{"StringEquals": {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}}},
	}}}
	require.NoError(t, service.WritePolicy(t.Context(), policy, false))
	require.NoError(t, service.AttachPolicyToUser(t.Context(), policy.DisplayName, "alice"))
	ctx := auth.WithPrincipalTags(t.Context(), principaltags.Tags{"team": "blue"})
	prepared, err := auth.PrepareAuthorization(ctx, service, "alice")
	require.NoError(t, err)
	node := permissions.Node{Permission: permissions.Permission{
		Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "blue/document"), ObjectMetadata: map[string]string{"team": "blue"},
	}}
	require.True(t, prepared.CanAuthorize(node))
	response, err := prepared.Authorize(ctx, &auth.AuthorizationRequest{Username: "alice", RequiredPermissions: node})
	require.NoError(t, err)
	require.True(t, response.Allowed)
	response, err = service.Authorize(t.Context(), &auth.AuthorizationRequest{Username: "alice", RequiredPermissions: node})
	require.NoError(t, err)
	require.False(t, response.Allowed, "independent credentials do not inherit PrincipalTags")
}
