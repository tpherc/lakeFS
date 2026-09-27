package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func TestObjectMetadataConditionLookup(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		metadata map[string]string
		field    string
		operator string
		pattern  string
		matches  bool
	}{
		{"exact key", map[string]string{"dcs:cls": "S"}, "lakefs:ObjectMetadata/dcs:cls", "StringLike", "S", true},
		{"key is case sensitive", map[string]string{"dcs:cls": "S"}, "lakefs:ObjectMetadata/DCS:CLS", "StringLike", "S", false},
		{"namespace is case sensitive", map[string]string{"dcs:cls": "S"}, "lakefs:objectmetadata/dcs:cls", "StringLike", "S", false},
		{"value is case sensitive", map[string]string{"dcs:cls": "s"}, "lakefs:ObjectMetadata/dcs:cls", "StringLike", "S", false},
		{"missing", nil, "lakefs:ObjectMetadata/dcs:cls", "StringLike", "*", false},
		{"missing negated", nil, "lakefs:ObjectMetadata/dcs:cls", "StringNotLike", "S", false},
		{"empty value exists", map[string]string{"dcs:cls": ""}, "lakefs:ObjectMetadata/dcs:cls", "StringLike", "", true},
		{"empty negated", map[string]string{"dcs:cls": ""}, "lakefs:ObjectMetadata/dcs:cls", "StringNotLike", "S", true},
		{"negated values", map[string]string{"dcs:cls": "S"}, "lakefs:ObjectMetadata/dcs:cls", "StringNotLike", "S", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conditionCtx := permissionConditionContext(t.Context(), permissions.Permission{
				Action: permissions.ReadObjectAction, ObjectMetadata: tt.metadata,
			})
			matched, err := EvaluateConditions(map[string]map[string][]string{
				tt.operator: {tt.field: {tt.pattern}},
			}, conditionCtx)
			require.NoError(t, err)
			require.Equal(t, tt.matches, matched)
		})
	}
}

func TestObjectMetadataClearancePolicies(t *testing.T) {
	t.Parallel()
	classifications := []string{"U", "R", "S", "TS"}
	var statements model.Statements
	for i, classification := range classifications {
		statements = append(statements, model.Statement{
			Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*",
			Condition: map[string]map[string][]string{"StringLike": {
				"aws:PrincipalTag/clr":          classifications[i:],
				"lakefs:ObjectMetadata/dcs:cls": {classification},
			}},
		})
	}
	policies := []*model.Policy{{Statement: statements}}
	for clearanceIndex, clearance := range classifications {
		for classificationIndex, classification := range classifications {
			t.Run(clearance+" reads "+classification, func(t *testing.T) {
				ctx := WithRequestConditionContext(WithPrincipalTags(t.Context(), principaltags.Tags{"clr": clearance}), "192.0.2.1")
				permission := permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "document"), ObjectMetadata: map[string]string{"dcs:cls": classification}}
				result := CheckPermissions(ctx, permissions.Node{Permission: permission}, "alice", policies, &MissingPermissions{})
				expected := CheckNeutral
				if clearanceIndex >= classificationIndex {
					expected = CheckAllow
				}
				require.Equal(t, expected, result)
			})
		}
	}
	for _, tt := range []struct {
		name     string
		tags     principaltags.Tags
		metadata map[string]string
	}{
		{"missing user clearance", nil, map[string]string{"dcs:cls": "U"}},
		{"unknown user clearance", principaltags.Tags{"clr": "unknown"}, map[string]string{"dcs:cls": "U"}},
		{"missing object classification", principaltags.Tags{"clr": "TS"}, nil},
		{"unknown object classification", principaltags.Tags{"clr": "TS"}, map[string]string{"dcs:cls": "unknown"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithRequestConditionContext(WithPrincipalTags(t.Context(), tt.tags), "")
			permission := permissions.Permission{Action: permissions.ReadObjectAction, Resource: "*", ObjectMetadata: tt.metadata}
			require.Equal(t, CheckNeutral, CheckPermissions(ctx, permissions.Node{Permission: permission}, "alice", policies, &MissingPermissions{}))
		})
	}
}

func TestObjectMetadataExplicitDenyOverridesAllow(t *testing.T) {
	t.Parallel()
	policies := []*model.Policy{{Statement: model.Statements{
		{Effect: model.StatementEffectAllow, Action: []string{"fs:*"}, Resource: "*"},
		{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: "*", Condition: map[string]map[string][]string{"StringLike": {"lakefs:ObjectMetadata/dcs:cls": {"TS"}}}},
	}}}
	permission := permissions.Permission{Action: permissions.ReadObjectAction, Resource: "*", ObjectMetadata: map[string]string{"dcs:cls": "TS"}}
	audit := &MissingPermissions{}
	require.Equal(t, CheckDeny, CheckPermissions(t.Context(), permissions.Node{Permission: permission}, "alice", policies, audit))
	require.Equal(t, []string{permissions.ReadObjectAction}, audit.Denied)
}

func TestObjectMetadataIsolatedAcrossPermissionLeaves(t *testing.T) {
	t.Parallel()
	source := permissions.Node{Permission: permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn("repo", "source"), ObjectMetadata: map[string]string{"dcs:cls": "S"}}}
	allowCondition := map[string]map[string][]string{"StringLike": {"lakefs:ObjectMetadata/dcs:cls": {"S"}}}
	for _, action := range []string{permissions.ReadObjectAction, permissions.WriteObjectAction, permissions.DeleteObjectAction, permissions.ListObjectsAction} {
		t.Run(action, func(t *testing.T) {
			metadata := map[string]string{"dcs:cls": "S"}
			if action == permissions.ReadObjectAction {
				metadata = nil
			}
			destination := permissions.Node{Permission: permissions.Permission{Action: action, Resource: permissions.ObjectArn("repo", "destination"), ObjectMetadata: metadata}}
			for _, nodes := range [][]permissions.Node{{source, destination}, {destination, source}} {
				allowPolicies := []*model.Policy{{Statement: model.Statements{{Effect: model.StatementEffectAllow, Action: []string{"fs:*"}, Resource: "*", Condition: allowCondition}}}}
				require.Equal(t, CheckNeutral, CheckPermissions(t.Context(), permissions.Node{Type: permissions.NodeTypeAnd, Nodes: nodes}, "alice", allowPolicies, &MissingPermissions{}))
				orPolicies := []*model.Policy{{Statement: model.Statements{
					{Effect: model.StatementEffectAllow, Action: []string{"fs:*"}, Resource: permissions.ObjectArn("repo", "source"), Condition: allowCondition},
					{Effect: model.StatementEffectDeny, Action: []string{"fs:*"}, Resource: permissions.ObjectArn("repo", "destination"), Condition: allowCondition},
				}}}
				require.Equal(t, CheckAllow, CheckPermissions(t.Context(), permissions.Node{Type: permissions.NodeTypeOr, Nodes: nodes}, "alice", orPolicies, &MissingPermissions{}))
			}
		})
	}
}

func TestObjectMetadataContextOwnership(t *testing.T) {
	t.Parallel()
	requestCtx := NewConditionContextWithFields(map[string]string{"SourceIp": "192.0.2.1", "lakefs:ObjectMetadata/spoofed": "untrusted"})
	requestCtx.AddPrincipalTags(principaltags.Tags{"clr": "S"})
	requestCtx.objectMetadata = map[string]string{"stale": "TS"}
	ctx := context.WithValue(t.Context(), contextKeyConditionContext, requestCtx)
	metadata := map[string]string{"dcs:cls": "S"}
	conditionCtx := permissionConditionContext(ctx, permissions.Permission{Action: permissions.ReadObjectAction, ObjectMetadata: metadata})
	metadata["dcs:cls"] = "U"
	requestCtx.Fields["SourceIp"] = "changed"
	requestCtx.AddPrincipalTags(principaltags.Tags{"clr": "U"})
	for field, expected := range map[string]string{"lakefs:ObjectMetadata/dcs:cls": "S", "aws:PrincipalTag/clr": "S", "SourceIp": "192.0.2.1"} {
		value, found := conditionCtx.Lookup(field)
		require.True(t, found)
		require.Equal(t, expected, value)
	}
	for _, field := range []string{"lakefs:ObjectMetadata/spoofed", "lakefs:ObjectMetadata/stale"} {
		_, found := conditionCtx.Lookup(field)
		require.False(t, found, field)
	}
	encoded, err := json.Marshal(permissions.Permission{Action: permissions.ReadObjectAction, ObjectMetadata: metadata})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "dcs:cls", "trusted metadata is not an API field")
}

func TestAuthorizationLogsExcludeObjectMetadataValues(t *testing.T) {
	// Logging configuration is global: keep this test serial.
	path := filepath.Join(t.TempDir(), "authorization.log")
	require.NoError(t, logging.SetOutputs([]string{path}, 0, 0))
	previousLevel := logging.Level()
	logging.SetLevel("debug")
	t.Cleanup(func() {
		logging.SetLevel(previousLevel)
		require.NoError(t, logging.SetOutputs([]string{"-"}, 0, 0))
	})
	const metadataValue = "confidential-object-attribute"
	ctx := WithRequestConditionContext(t.Context(), "192.0.2.1")
	policies := []*model.Policy{{Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*",
		Condition: map[string]map[string][]string{"IpAddress": {"lakefs:ObjectMetadata/dcs:cls": {"192.0.2.0/24"}}},
	}}}}
	permission := permissions.Permission{Action: permissions.ReadObjectAction, Resource: "*", ObjectMetadata: map[string]string{"dcs:cls": metadataValue}}
	require.Equal(t, CheckDeny, CheckPermissions(ctx, permissions.Node{Permission: permission}, "alice", policies, &MissingPermissions{}))
	logged, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(logged), "Failed to evaluate conditions")
	require.Contains(t, string(logged), "192.0.2.1")
	require.NotContains(t, string(logged), metadataValue)
}
