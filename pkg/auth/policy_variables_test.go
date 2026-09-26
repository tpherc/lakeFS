package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/permissions"
)

type policyVariableService struct {
	policies  []*model.Policy
	listCalls atomic.Int64
}

func (s *policyVariableService) ListEffectivePolicies(context.Context, string, *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	s.listCalls.Add(1)
	return s.policies, nil, nil
}

func (s *policyVariableService) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
	policies, err := AuthorizationPolicies(ctx, req, s.ListEffectivePolicies)
	if err != nil {
		return nil, err
	}
	ctx = WithRequestConditionContext(ctx, req.ClientIP)
	result := CheckRequestPermissions(ctx, req, policies, &MissingPermissions{})
	return &AuthorizationResponse{Allowed: result == CheckAllow}, nil
}

func policyVariablePolicies(statements ...model.Statement) []*model.Policy {
	return []*model.Policy{{Statement: statements}}
}

func policyVariableRead(resource string, condition map[string]map[string][]string) model.Statement {
	return model.Statement{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: resource, Condition: condition}
}

func policyVariableReadNode(path string, metadata map[string]string) permissions.Node {
	return permissions.Node{Permission: permissions.Permission{
		Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", path), ObjectMetadata: metadata,
	}}
}

func policyVariableResourceList(t testing.TB, resources ...string) string {
	t.Helper()
	encoded, err := json.Marshal(resources)
	require.NoError(t, err)
	return string(encoded)
}

func TestPolicyVariablesAuthorizationPaths(t *testing.T) {
	t.Parallel()
	tagResource := permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*")
	tagCondition := map[string]map[string][]string{OperatorNameStringEquals: {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}}}
	tests := []struct {
		name      string
		username  string
		resource  string
		condition map[string]map[string][]string
		tags      principaltags.Tags
		path      string
		metadata  map[string]string
		candidate bool
		allowed   bool
	}{
		{name: "legacy unknown placeholder stays literal", resource: permissions.ObjectArn("repo", "${unknown}/doc"), path: "${unknown}/doc", candidate: true, allowed: true},
		{name: "legacy user inside unknown wrapper", resource: permissions.ObjectArn("repo", "${outer/${user}}/doc"), path: "${outer/alice}/doc", candidate: true, allowed: true},
		{name: "legacy user in ARN header", username: "fs", resource: "arn:lakefs:${user}:::repository/repo/object/document", path: "document", candidate: true, allowed: true},
		{name: "legacy user supplies full ARN", username: permissions.ObjectArn("repo", "document"), resource: "${user}", path: "document", candidate: true, allowed: true},
		{name: "tag resource", resource: tagResource, tags: principaltags.Tags{"team": "research"}, path: "research/doc", candidate: true, allowed: true},
		{name: "different resource", resource: tagResource, tags: principaltags.Tags{"team": "research"}, path: "finance/doc"},
		{name: "missing resource tag", resource: tagResource, path: "research/doc"},
		{name: "empty resource tag", resource: permissions.ObjectArn("repo", "home/${aws:PrincipalTag/team}/*"), tags: principaltags.Tags{"team": ""}, path: "home//doc", candidate: true, allowed: true},
		{name: "mixed user and tag", resource: permissions.ObjectArn("repo", "${user}/${aws:PrincipalTag/team}/*"), tags: principaltags.Tags{"team": "research"}, path: "alice/research/doc", candidate: true, allowed: true},
		{name: "mixed legacy username wildcard", username: "ali*", resource: permissions.ObjectArn("repo", "${user}/${aws:PrincipalTag/team}/*"), tags: principaltags.Tags{"team": "research"}, path: "alice/research/doc", candidate: true, allowed: true},
		{name: "username is not rescanned", username: "${aws:PrincipalTag/team}", resource: permissions.ObjectArn("repo", "${user}/${aws:PrincipalTag/team}/*"), tags: principaltags.Tags{"team": "research"}, path: "${aws:PrincipalTag/team}/research/doc", candidate: true, allowed: true},
		{name: "tag value is not rescanned", resource: tagResource, tags: principaltags.Tags{"team": "${user}"}, path: "${user}/doc", candidate: true, allowed: true},
		{name: "missing sibling resource", resource: policyVariableResourceList(t, tagResource, permissions.ObjectArn("repo", "public/*")), path: "public/doc", candidate: true, allowed: true},
		{name: "metadata matches tag", resource: tagResource, condition: tagCondition, tags: principaltags.Tags{"team": "research"}, path: "research/doc", metadata: map[string]string{"team": "research"}, candidate: true, allowed: true},
		{name: "metadata differs from tag", resource: tagResource, condition: tagCondition, tags: principaltags.Tags{"team": "research"}, path: "research/doc", metadata: map[string]string{"team": "finance"}, candidate: true},
		{name: "metadata absent", resource: tagResource, condition: tagCondition, tags: principaltags.Tags{"team": "research"}, path: "research/doc", candidate: true},
		{name: "missing RHS tag only", resource: "*", condition: tagCondition, path: "research/doc", metadata: map[string]string{"team": "research"}, candidate: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			username := test.username
			if username == "" {
				username = "alice"
			}
			ctx := WithPrincipalTags(t.Context(), test.tags)
			policies := policyVariablePolicies(policyVariableRead(test.resource, test.condition))
			service := &policyVariableService{policies: policies}
			prepared, err := PrepareAuthorization(ctx, service, username)
			require.NoError(t, err)
			node := policyVariableReadNode(test.path, test.metadata)
			require.Equal(t, test.candidate, prepared.CanAuthorize(node))
			response, err := prepared.Authorize(ctx, &AuthorizationRequest{Username: username, RequiredPermissions: node})
			require.NoError(t, err)
			require.Equal(t, test.allowed, response.Allowed)
			require.EqualValues(t, 1, service.listCalls.Load())
			conditionCtx := NewRequestConditionContext(ctx, "")
			conditionCtx.objectMetadata = maps.Clone(test.metadata)
			require.Equal(t, test.candidate, HasPermissionOnResource(node.Permission.Resource, username, policies, node.Permission.Action, conditionCtx))
			allowed, err := CheckPermission(node.Permission.Resource, username, policies, node.Permission.Action, conditionCtx)
			require.NoError(t, err)
			require.Equal(t, test.allowed, allowed)
			result := CheckPermissions(ctx, node, username, policies, &MissingPermissions{})
			require.Equal(t, test.allowed, result == CheckAllow)
		})
	}
}

func TestPolicyVariablesPrivateLookupCannotBeSpoofed(t *testing.T) {
	t.Parallel()
	resource := permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*")
	policies := policyVariablePolicies(policyVariableRead(resource, nil))
	ctx := NewConditionContextWithFields(map[string]string{"aws:PrincipalTag/team": "research", "AWS:PRINCIPALTAG/TEAM": "research"})
	target := permissions.ObjectArn("repo", "research/doc")
	require.False(t, HasPermissionOnResource(target, "alice", policies, permissions.ReadObjectAction, ctx))
	allowed, err := CheckPermission(target, "alice", policies, permissions.ReadObjectAction, ctx)
	require.NoError(t, err)
	require.False(t, allowed)
	ctx.AddPrincipalTags(principaltags.Tags{"team": "finance"})
	allowed, err = CheckPermission(target, "alice", policies, permissions.ReadObjectAction, ctx)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestPolicyVariablesInvalidSnapshotCannotBeSkipped(t *testing.T) {
	t.Parallel()
	valid := policyVariableRead("*", nil)
	malformed := permissions.ObjectArn("repo", "${aws:PrincipalTag/team")
	tests := []struct {
		name       string
		statements model.Statements
	}{
		{"unrelated statement", model.Statements{valid, {Effect: model.StatementEffectAllow, Action: []string{permissions.WriteObjectAction}, Resource: malformed}}},
		{"false condition", model.Statements{valid, policyVariableRead(malformed, map[string]map[string][]string{OperatorNameStringEquals: {"missing": {"value"}}})}},
		{"matching resource sibling", model.Statements{policyVariableRead(policyVariableResourceList(t, "*", malformed), nil)}},
		{"matching condition sibling", model.Statements{policyVariableRead("*", map[string]map[string][]string{OperatorNameStringLike: {"SourceIp": {"*", "${aws:PrincipalTag/team"}}})}},
		{"dynamic action", model.Statements{valid, {Effect: model.StatementEffectAllow, Action: []string{"${aws:PrincipalTag/action}"}, Resource: "*"}}},
		{"dynamic effect", model.Statements{valid, {Effect: "${aws:PrincipalTag/effect}", Action: []string{permissions.ReadObjectAction}, Resource: "*"}}},
		{"dynamic field", model.Statements{valid, policyVariableRead("*", map[string]map[string][]string{OperatorNameStringEquals: {"${aws:PrincipalTag/field}": {"value"}}})}},
		{"dynamic IP", model.Statements{valid, policyVariableRead("*", map[string]map[string][]string{OperatorNameIpAddress: {"SourceIp": {"${aws:PrincipalTag/ip}"}}})}},
		{"user in condition", model.Statements{valid, policyVariableRead("*", map[string]map[string][]string{OperatorNameStringEquals: {"SourceIp": {"${user}"}}})}},
		{"dynamic service", model.Statements{valid, policyVariableRead("arn:lakefs:${aws:PrincipalTag/service}:::repository/repo/object/*", nil)}},
		{"dynamic account", model.Statements{valid, policyVariableRead("arn:lakefs:fs::${aws:PrincipalTag/account}:repository/repo/object/*", nil)}},
		{"whole resource variable", model.Statements{valid, policyVariableRead("${aws:PrincipalTag/arn}", nil)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policies := policyVariablePolicies(test.statements...)
			require.Error(t, ValidatePolicyTemplates(policies[0]))
			service := &policyVariableService{policies: policies}
			prepared, err := PrepareAuthorization(t.Context(), service, "alice")
			require.Error(t, err)
			require.Nil(t, prepared)
			node := policyVariableReadNode("document", nil)
			conditionCtx := NewConditionContext("192.0.2.1")
			require.False(t, HasPermissionOnResource(node.Permission.Resource, "alice", policies, node.Permission.Action, conditionCtx))
			allowed, err := CheckPermission(node.Permission.Resource, "alice", policies, node.Permission.Action, conditionCtx)
			require.Error(t, err)
			require.False(t, allowed)
			for _, tree := range []permissions.Node{
				node,
				{Type: permissions.NodeTypeOr, Nodes: []permissions.Node{node, node}},
				{Type: permissions.NodeTypeAnd, Nodes: []permissions.Node{{Permission: permissions.Permission{Action: permissions.WriteObjectAction, Resource: "other"}}, node}},
			} {
				require.Equal(t, CheckDeny, CheckPermissions(t.Context(), tree, "alice", policies, &MissingPermissions{}))
			}
		})
	}
}

func TestPolicyVariablesUnsafeRuntimeValueCannotBeSkipped(t *testing.T) {
	t.Parallel()
	const secret = "sensitive-tag-value*"
	for _, test := range []struct {
		name      string
		statement model.Statement
	}{
		{"resource sibling", policyVariableRead(policyVariableResourceList(t, "*", permissions.ObjectArn("repo", "${aws:PrincipalTag/unsafe}/*")), nil)},
		{"condition sibling", policyVariableRead("*", map[string]map[string][]string{OperatorNameStringLike: {"SourceIp": {"*", "${aws:PrincipalTag/unsafe}"}}})},
		{"unresolved before invalid", policyVariableRead("*", map[string]map[string][]string{OperatorNameStringNotEquals: {"SourceIp": {"${aws:PrincipalTag/missing}", "${aws:PrincipalTag/unsafe}"}}})},
	} {
		t.Run(test.name, func(t *testing.T) {
			policies := policyVariablePolicies(policyVariableRead("*", nil), test.statement)
			require.NoError(t, ValidatePolicyTemplates(policies[0]))
			ctx := WithPrincipalTags(t.Context(), principaltags.Tags{"unsafe": secret})
			prepared, err := PrepareAuthorization(ctx, &policyVariableService{policies: policies}, "alice")
			require.ErrorIs(t, err, policytemplate.ErrWildcardValue)
			require.NotContains(t, err.Error(), secret)
			require.Nil(t, prepared)
			node := policyVariableReadNode("document", nil)
			allowed, err := CheckPermission(node.Permission.Resource, "alice", policies, node.Permission.Action, NewRequestConditionContext(ctx, "192.0.2.1"))
			require.ErrorIs(t, err, policytemplate.ErrWildcardValue)
			require.NotContains(t, err.Error(), secret)
			require.False(t, allowed)
			require.Equal(t, CheckDeny, CheckPermissions(ctx, node, "alice", policies, &MissingPermissions{}))
		})
	}
}

func TestPolicyVariablesDenyPrecedence(t *testing.T) {
	t.Parallel()
	allow := policyVariableRead(permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*"), nil)
	deny := policyVariableRead(permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/secret/*"), nil)
	deny.Effect = model.StatementEffectDeny
	for _, statements := range []model.Statements{{allow, deny}, {deny, allow}} {
		policies := policyVariablePolicies(statements...)
		ctx := WithPrincipalTags(t.Context(), principaltags.Tags{"team": "research"})
		prepared, err := PrepareAuthorization(ctx, &policyVariableService{policies: policies}, "alice")
		require.NoError(t, err)
		for _, path := range []string{"research/public/doc", "research/secret/doc"} {
			node := policyVariableReadNode(path, nil)
			require.True(t, prepared.CanAuthorize(node))
			response, err := prepared.Authorize(ctx, &AuthorizationRequest{Username: "alice", RequiredPermissions: node})
			require.NoError(t, err)
			expected := path == "research/public/doc"
			require.Equal(t, expected, response.Allowed)
			allowed, err := CheckPermission(node.Permission.Resource, "alice", policies, node.Permission.Action, NewRequestConditionContext(ctx, ""))
			require.NoError(t, err)
			require.Equal(t, expected, allowed)
		}
	}
}

func TestPolicyVariablesPreparedSnapshotPersists(t *testing.T) {
	t.Parallel()
	policies := policyVariablePolicies(policyVariableRead(permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*"), map[string]map[string][]string{
		OperatorNameStringEquals: {
			"aws:PrincipalTag/team":      {"research"},
			"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"},
		},
	}))
	service := &policyVariableService{policies: policies}
	ctx := WithPrincipalTags(t.Context(), principaltags.Tags{"team": "research"})
	prepared, err := PrepareAuthorization(ctx, service, "alice")
	require.NoError(t, err)
	// Mutating source models would make reparsing fail; the prepared request must use owned syntax.
	policies[0].Statement[0].Resource = "${aws:PrincipalTag/team"
	policies[0].Statement[0].Action[0] = permissions.WriteObjectAction
	policies[0].Statement[0].Condition[OperatorNameStringEquals]["aws:PrincipalTag/team"][0] = "finance"
	ctx = WithPrincipalTags(ctx, principaltags.Tags{"team": "finance"})
	for _, test := range []struct {
		metadata string
		allowed  bool
	}{{"research", true}, {"finance", false}, {"research", true}} {
		node := policyVariableReadNode("research/doc", map[string]string{"team": test.metadata})
		require.True(t, prepared.CanAuthorize(node))
		response, err := prepared.Authorize(ctx, &AuthorizationRequest{Username: "alice", RequiredPermissions: node})
		require.NoError(t, err)
		require.Equal(t, test.allowed, response.Allowed, "both RHS binding and LHS principal lookup must use the prepared tags")
	}
	require.EqualValues(t, 1, service.listCalls.Load())
}

func TestPolicyVariablesConcurrentPreparedRequests(t *testing.T) {
	t.Parallel()
	policies := policyVariablePolicies(policyVariableRead(permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*"), map[string]map[string][]string{
		OperatorNameStringEquals: {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}},
	}))
	before, err := json.Marshal(policies)
	require.NoError(t, err)
	service := &policyVariableService{policies: policies}
	var workers sync.WaitGroup
	for _, team := range []string{"research", "finance", "engineering", "analytics"} {
		workers.Go(func() {
			ctx := WithPrincipalTags(t.Context(), principaltags.Tags{"team": team})
			prepared, err := PrepareAuthorization(ctx, service, "alice")
			if err != nil {
				t.Error(err)
				return
			}
			for i := 0; i < 20; i++ {
				for _, target := range []string{team, "other-team"} {
					node := policyVariableReadNode(target+"/doc", map[string]string{"team": target})
					expected := target == team
					if prepared.CanAuthorize(node) != expected {
						t.Errorf("candidate leaked between teams %s and %s", team, target)
					}
					response, err := prepared.Authorize(ctx, &AuthorizationRequest{Username: "alice", RequiredPermissions: node})
					if err != nil || response == nil || response.Allowed != expected {
						t.Errorf("team %s target %s: response=%v, error=%v", team, target, response, err)
					}
				}
			}
		})
	}
	workers.Wait()
	require.EqualValues(t, 4, service.listCalls.Load())
	after, err := json.Marshal(policies)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "binding cannot mutate shared policies")
}

func TestPolicyVariablesPreparedPermissionCheckerReusesSnapshot(t *testing.T) {
	t.Parallel()
	policies := policyVariablePolicies(model.Statement{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ListRepositoriesAction}, Resource: permissions.RepoArn("${aws:PrincipalTag/team}-*"),
		Condition: map[string]map[string][]string{OperatorNameStringEquals: {"aws:PrincipalTag/team": {"${aws:PrincipalTag/team}"}}},
	})
	ctx := NewConditionContext("")
	ctx.AddPrincipalTags(principaltags.Tags{"team": "research"})
	checker, err := PreparePermissionChecker("alice", policies, ctx)
	require.NoError(t, err)
	ctx.AddPrincipalTags(principaltags.Tags{"team": "finance*"})
	policies[0].Statement[0].Condition[OperatorNameStringEquals]["aws:PrincipalTag/team"][0] = "${aws:PrincipalTag/unterminated"
	for i := 0; i < 20; i++ {
		allowed, err := checker.Check(permissions.RepoArn(fmt.Sprintf("research-%d", i)), permissions.ListRepositoriesAction)
		require.NoError(t, err)
		require.True(t, allowed)
		allowed, err = checker.Check(permissions.RepoArn(fmt.Sprintf("finance-%d", i)), permissions.ListRepositoriesAction)
		require.NoError(t, err)
		require.False(t, allowed)
	}
}

func TestPolicyVariablesPermissionMetadataIsolation(t *testing.T) {
	t.Parallel()
	condition := map[string]map[string][]string{OperatorNameStringEquals: {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}}}
	read := policyVariableRead("*", condition)
	write := read
	write.Action = []string{permissions.WriteObjectAction}
	policies := policyVariablePolicies(read, write)
	ctx := WithPrincipalTags(t.Context(), principaltags.Tags{"team": "research"})
	prepared, err := PrepareAuthorization(ctx, &policyVariableService{policies: policies}, "alice")
	require.NoError(t, err)
	source := policyVariableReadNode("source", map[string]string{"team": "research"})
	for _, test := range []struct {
		name        string
		action      string
		destination string
		allowed     bool
	}{
		{"both readable", permissions.ReadObjectAction, "research", true},
		{"destination differs", permissions.ReadObjectAction, "finance", false},
		{"source metadata does not reach destination write", permissions.WriteObjectAction, "research", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := policyVariableReadNode("destination", map[string]string{"team": test.destination})
			destination.Permission.Action = test.action
			tree := permissions.Node{Type: permissions.NodeTypeAnd, Nodes: []permissions.Node{source, destination}}
			require.True(t, prepared.CanAuthorize(tree))
			response, err := prepared.Authorize(ctx, &AuthorizationRequest{Username: "alice", RequiredPermissions: tree})
			require.NoError(t, err)
			require.Equal(t, test.allowed, response.Allowed)
			require.Equal(t, test.allowed, CheckPermissions(ctx, tree, "alice", policies, &MissingPermissions{}) == CheckAllow)
		})
	}
}

func BenchmarkPolicyVariablesPreparedListing(b *testing.B) {
	policies := policyVariablePolicies(model.Statement{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ListRepositoriesAction}, Resource: permissions.RepoArn("${aws:PrincipalTag/team}-*"),
		Condition: map[string]map[string][]string{OperatorNameStringEquals: {"aws:PrincipalTag/team": {"${aws:PrincipalTag/team}"}}},
	})
	ctx := NewConditionContext("")
	ctx.AddPrincipalTags(principaltags.Tags{"team": "research"})
	resources := make([]string, 100)
	for i := range resources {
		resources[i] = permissions.RepoArn(fmt.Sprintf("research-%d", i))
	}
	b.Run("prepared", func(b *testing.B) {
		checker, err := PreparePermissionChecker("alice", policies, ctx)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			for _, resource := range resources {
				allowed, err := checker.Check(resource, permissions.ListRepositoriesAction)
				if err != nil || !allowed {
					b.Fatalf("check failed: allowed=%v, error=%v", allowed, err)
				}
			}
		}
	})
	b.Run("prepare_per_entry", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, resource := range resources {
				allowed, err := CheckPermission(resource, "alice", policies, permissions.ListRepositoriesAction, ctx)
				if err != nil || !allowed {
					b.Fatalf("check failed: allowed=%v, error=%v", allowed, err)
				}
			}
		}
	})
}

func TestPolicyVariablesMissingNegatedDenyDoesNotMatch(t *testing.T) {
	t.Parallel()
	for _, operator := range []string{OperatorNameStringNotEquals, OperatorNameStringNotLike} {
		t.Run(operator, func(t *testing.T) {
			for _, test := range []struct {
				name    string
				values  []string
				tags    principaltags.Tags
				allowed bool
			}{
				{"missing RHS", []string{"${aws:PrincipalTag/team}"}, nil, true},
				{"matching literal before missing RHS", []string{"research", "${aws:PrincipalTag/team}"}, nil, true},
				{"matching literal after missing RHS", []string{"${aws:PrincipalTag/team}", "research"}, nil, true},
				{"mismatching literal with missing RHS", []string{"finance", "${aws:PrincipalTag/team}"}, nil, true},
				{"present matching RHS", []string{"${aws:PrincipalTag/team}"}, principaltags.Tags{"team": "research"}, true},
				{"present mismatching RHS activates Deny", []string{"${aws:PrincipalTag/team}"}, principaltags.Tags{"team": "finance"}, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					deny := policyVariableRead("*", map[string]map[string][]string{operator: {"lakefs:ObjectMetadata/team": test.values}})
					deny.Effect = model.StatementEffectDeny
					policies := policyVariablePolicies(policyVariableRead("*", nil), deny)
					ctx := WithPrincipalTags(t.Context(), test.tags)
					node := policyVariableReadNode("document", map[string]string{"team": "research"})
					result := CheckPermissions(ctx, node, "alice", policies, &MissingPermissions{})
					expectedResult := CheckAllow
					if !test.allowed {
						expectedResult = CheckDeny
					}
					require.Equal(t, expectedResult, result)

					conditionCtx := NewRequestConditionContext(ctx, "")
					conditionCtx.objectMetadata = maps.Clone(node.Permission.ObjectMetadata)
					allowed, err := CheckPermission(node.Permission.Resource, "alice", policies, node.Permission.Action, conditionCtx)
					require.NoError(t, err)
					require.Equal(t, test.allowed, allowed)

					prepared, err := PrepareAuthorization(ctx, &policyVariableService{policies: policies}, "alice")
					require.NoError(t, err)
					require.True(t, prepared.CanAuthorize(node), "the broad Allow is always a candidate")
					response, err := prepared.Authorize(ctx, &AuthorizationRequest{Username: "alice", RequiredPermissions: node})
					require.NoError(t, err)
					require.Equal(t, test.allowed, response.Allowed)
				})
			}
		})
	}
}

func TestPolicyVariableResourceNamespaceCompatibility(t *testing.T) {
	t.Parallel()
	ctx := NewRequestConditionContext(WithPrincipalTags(t.Context(), principaltags.Tags{"team": "blue"}), "")
	for _, test := range []struct{ pattern, path string }{
		{"${AWS:PRINCIPALTAG/team}/doc", "blue/doc"},
		{"${awſ:PrincipalTag/team}/doc", "blue/doc"},
		{"${aws:PrincipalTags/team}/doc", "${aws:PrincipalTags/team}/doc"},
	} {
		policies := policyVariablePolicies(policyVariableRead(permissions.ObjectArn("repo", test.pattern), nil))
		allowed, err := CheckPermission(permissions.ObjectArn("repo", test.path), "alice", policies, permissions.ReadObjectAction, ctx)
		require.NoError(t, err)
		require.True(t, allowed, test.pattern)
	}
}
