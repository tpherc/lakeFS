package auth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/permissions"
)

type preparedPolicyService struct {
	policies       []*model.Policy
	listErr        error
	listCalls      int
	authorizeCalls int
	listedUsername string
	lastRequest    *AuthorizationRequest
}

func (s *preparedPolicyService) ListEffectivePolicies(_ context.Context, username string, _ *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	s.listCalls++
	s.listedUsername = username
	return s.policies, nil, s.listErr
}

func (s *preparedPolicyService) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
	s.authorizeCalls++
	s.lastRequest = req
	policies, err := AuthorizationPolicies(ctx, req, s.ListEffectivePolicies)
	if err != nil {
		return nil, err
	}
	result := CheckRequestPermissions(WithRequestConditionContext(ctx, req.ClientIP), req, policies, &MissingPermissions{})
	return &AuthorizationResponse{Allowed: result == CheckAllow}, nil
}

func TestPreparedAuthorizationCandidates(t *testing.T) {
	t.Parallel()
	object := permissions.ObjectArn("repo", "document")
	conditional := map[string]map[string][]string{"StringLike": {"lakefs:ObjectMetadata/dcs:cls": {"S"}}}
	allow := model.Statement{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: object}
	for _, tt := range []struct {
		name       string
		statements model.Statements
		candidate  bool
		allowed    bool
		prepareErr error
	}{
		{"no policies", nil, false, false, nil},
		{"unconditional allow", model.Statements{allow}, true, true, nil},
		{"different action", model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.WriteObjectAction}, Resource: object}}, false, false, nil},
		{"different resource", model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn("other", "document")}}, false, false, nil},
		{"deny alone", model.Statements{{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: object}}, false, false, nil},
		{"conditional allow requires metadata", model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: object, Condition: conditional}}, true, false, nil},
		{"deny overrides candidate", model.Statements{allow, {Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: object}}, true, false, nil},
		{"unmatched conditional deny", model.Statements{allow, {Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: object, Condition: conditional}}, true, true, nil},
		{"invalid condition fails preparation", model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: object, Condition: map[string]map[string][]string{"unknown": {"field": {"value"}}}}}, false, false, ErrUnsupportedConditionOperator},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := &preparedPolicyService{policies: []*model.Policy{{Statement: tt.statements}}}
			prepared, err := PrepareAuthorization(t.Context(), service, "alice")
			if tt.prepareErr != nil {
				require.ErrorIs(t, err, tt.prepareErr)
				require.Nil(t, prepared)
				require.Zero(t, service.authorizeCalls)
				return
			}
			require.NoError(t, err)
			node := permissions.Node{Permission: permissions.Permission{Action: permissions.ReadObjectAction, Resource: object}}
			require.Equal(t, tt.candidate, prepared.CanAuthorize(node))
			response, err := prepared.Authorize(t.Context(), &AuthorizationRequest{Username: "alice", RequiredPermissions: node})
			require.NoError(t, err)
			require.Equal(t, tt.allowed, response.Allowed)
			require.Equal(t, 1, service.listCalls)
			require.Equal(t, 1, service.authorizeCalls, "the original authorizer must still run")
		})
	}
}

func TestPreparedAuthorizationPermissionTrees(t *testing.T) {
	t.Parallel()
	service := &preparedPolicyService{policies: []*model.Policy{{Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn("repo", "${user}/*"),
	}}}}}
	prepared, err := PrepareAuthorization(t.Context(), service, "alice")
	require.NoError(t, err)
	read := permissions.Node{Permission: permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "alice/document")}}
	write := permissions.Node{Permission: permissions.Permission{Action: permissions.WriteObjectAction, Resource: read.Permission.Resource}}
	for _, tt := range []struct {
		name      string
		node      permissions.Node
		candidate bool
	}{
		{"AND all candidates", permissions.Node{Type: permissions.NodeTypeAnd, Nodes: []permissions.Node{read, read}}, true},
		{"AND missing candidate", permissions.Node{Type: permissions.NodeTypeAnd, Nodes: []permissions.Node{read, write}}, false},
		{"OR one candidate", permissions.Node{Type: permissions.NodeTypeOr, Nodes: []permissions.Node{write, read}}, true},
		{"OR no candidate", permissions.Node{Type: permissions.NodeTypeOr, Nodes: []permissions.Node{write, write}}, false},
		{"empty AND", permissions.Node{Type: permissions.NodeTypeAnd}, true},
		{"empty OR", permissions.Node{Type: permissions.NodeTypeOr}, false},
		{"unknown node", permissions.Node{Type: permissions.NodeType(99)}, false},
	} {
		t.Run(tt.name, func(t *testing.T) { require.Equal(t, tt.candidate, prepared.CanAuthorize(tt.node)) })
	}
	require.Equal(t, 1, service.listCalls)
	require.Zero(t, service.authorizeCalls)
}

func TestPreparedAuthorizationReusesPoliciesWithoutCachingDecisions(t *testing.T) {
	t.Parallel()
	service := &preparedPolicyService{policies: []*model.Policy{{Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*",
		Condition: map[string]map[string][]string{"StringLike": {"lakefs:ObjectMetadata/dcs:cls": {"U"}}},
	}}}}}
	prepared, err := PrepareAuthorization(t.Context(), service, "alice")
	require.NoError(t, err)
	// A later service result must not replace policies already loaded for this request.
	service.policies = nil
	node := permissions.Node{Permission: permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "document"), ObjectMetadata: map[string]string{"dcs:cls": "U"}}}
	require.True(t, prepared.CanAuthorize(node))
	req := &AuthorizationRequest{Username: "alice", RequiredPermissions: node}
	response, err := prepared.Authorize(t.Context(), req)
	require.NoError(t, err)
	require.True(t, response.Allowed)
	require.Nil(t, req.policySnapshot, "caller request must not be mutated")
	require.NotSame(t, req, service.lastRequest)
	encoded, err := json.Marshal(service.lastRequest)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "StringLike", "policy snapshot is not a serialized request field")
	node.Permission.ObjectMetadata = map[string]string{"dcs:cls": "TS"}
	response, err = prepared.Authorize(t.Context(), &AuthorizationRequest{Username: "alice", RequiredPermissions: node})
	require.NoError(t, err)
	require.False(t, response.Allowed)
	require.Equal(t, 1, service.listCalls)
	require.Equal(t, 2, service.authorizeCalls)
}

func TestPreparedAuthorizationPolicyFailure(t *testing.T) {
	t.Parallel()
	service := &preparedPolicyService{listErr: errors.New("policy database unavailable")}
	prepared, err := PrepareAuthorization(t.Context(), service, "alice")
	require.ErrorIs(t, err, service.listErr)
	require.Nil(t, prepared)
	require.Zero(t, service.authorizeCalls)
}

func TestPreparedAuthorizationRejectsDifferentUser(t *testing.T) {
	t.Parallel()
	service := &preparedPolicyService{}
	prepared, err := PrepareAuthorization(t.Context(), service, "alice")
	require.NoError(t, err)
	response, err := prepared.Authorize(t.Context(), &AuthorizationRequest{Username: "bob"})
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.Nil(t, response)
	require.Zero(t, service.authorizeCalls)

	_, err = AuthorizationPolicies(t.Context(), &AuthorizationRequest{Username: "bob", policySnapshot: prepared.snapshot}, service.ListEffectivePolicies)
	require.NoError(t, err)
	require.Equal(t, 2, service.listCalls, "a mismatched snapshot must never supply another user's policies")
	require.Equal(t, "bob", service.listedUsername)
}
