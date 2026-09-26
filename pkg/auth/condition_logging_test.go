package auth_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func TestAuthorizationLogsExcludePrincipalTagValues(t *testing.T) {
	// Logging configuration is global: keep this test serial.
	path := filepath.Join(t.TempDir(), "authorization.log")
	require.NoError(t, logging.SetOutputs([]string{path}, 0, 0))
	previousLevel := logging.Level()
	logging.SetLevel("debug")
	t.Cleanup(func() {
		logging.SetLevel(previousLevel)
		require.NoError(t, logging.SetOutputs([]string{"-"}, 0, 0))
	})
	const tagValue = "confidential-principal-attribute"
	ctx := auth.WithRequestConditionContext(auth.WithPrincipalTags(t.Context(), principaltags.Tags{"clr": tagValue}), "192.0.2.1")
	policies := []*model.Policy{{Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{"fs:*"}, Resource: "*",
		Condition: map[string]map[string][]string{"IpAddress": {"aws:PrincipalTag/clr": {"192.0.2.0/24"}}},
	}}}}
	result := auth.CheckPermissions(ctx, permissions.Node{Type: permissions.NodeTypeNode, Permission: permissions.Permission{Action: "fs:ReadObject", Resource: "*"}}, "user", policies, &auth.MissingPermissions{})
	require.Equal(t, auth.CheckDeny, result)
	logged, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(logged), "Failed to evaluate conditions")
	require.Contains(t, string(logged), "192.0.2.1")
	require.NotContains(t, string(logged), tagValue)
}
