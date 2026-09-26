package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func TestPolicyVariablesValidateSnapshotBeforeBinding(t *testing.T) {
	t.Parallel()
	const unsafeTag = "private-team*"
	for _, test := range []struct {
		name      string
		statement model.Statement
	}{
		{"resource", policyVariableRead(permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*"), nil)},
		{"condition", policyVariableRead("*", map[string]map[string][]string{
			OperatorNameStringEquals: {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}},
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			policies := policyVariablePolicies(test.statement,
				policyVariableRead(permissions.ObjectArn("repo", "${aws:PrincipalTag/team"), nil))
			ctx := WithPrincipalTags(t.Context(), principaltags.Tags{"team": unsafeTag})

			prepared, err := PrepareAuthorization(ctx, &policyVariableService{policies: policies}, "alice")
			require.Nil(t, prepared)
			require.ErrorIs(t, err, policytemplate.ErrInvalidTemplate, "validate the later statement before binding an earlier one")
			require.NotErrorIs(t, err, policytemplate.ErrWildcardValue)
			require.NotContains(t, err.Error(), unsafeTag)

			checker, err := PreparePermissionChecker("alice", policies, NewRequestConditionContext(ctx, ""))
			require.Nil(t, checker)
			require.ErrorIs(t, err, policytemplate.ErrInvalidTemplate)
			require.NotErrorIs(t, err, policytemplate.ErrWildcardValue)
		})
	}
}

func BenchmarkPolicyVariablesReadOperation(b *testing.B) {
	ctx := WithPrincipalTags(b.Context(), principaltags.Tags{"team": "research"})
	service := &policyVariableService{policies: policyVariablePolicies(
		policyVariableRead(permissions.ObjectArn("repo", "${aws:PrincipalTag/team}/*"),
			map[string]map[string][]string{
				OperatorNameStringEquals: {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}},
			}),
	)}
	b.Run("preparation_only", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := PrepareAuthorization(ctx, service, "alice"); err != nil {
				b.Fatal(err)
			}
		}
	})

	for _, count := range []int{1, 1000, 10000} {
		requests := make([]AuthorizationRequest, count)
		for i := range requests {
			team := "research"
			if i%3 == 2 {
				team = "finance"
			}
			requests[i] = AuthorizationRequest{
				Username: "alice", ClientIP: "192.0.2.1",
				RequiredPermissions: policyVariableReadNode(fmt.Sprintf("research/object-%d", i), map[string]string{"team": team}),
			}
		}
		b.Run(fmt.Sprintf("objects_%d", count), func(b *testing.B) {
			b.Run("prepare_once_per_operation", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					prepared, err := PrepareAuthorization(ctx, service, "alice")
					if err != nil {
						b.Fatal(err)
					}
					for i := range requests {
						response, err := prepared.Authorize(ctx, &requests[i])
						if err != nil || response == nil || response.Allowed != (i%3 != 2) {
							b.Fatalf("Authorize object %d: response=%v, error=%v", i, response, err)
						}
					}
				}
				b.ReportMetric(float64(count), "objects/op")
			})
			b.Run("prepare_per_object", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					for i := range requests {
						response, err := service.Authorize(ctx, &requests[i])
						if err != nil || response == nil || response.Allowed != (i%3 != 2) {
							b.Fatalf("Authorize object %d: response=%v, error=%v", i, response, err)
						}
					}
				}
				b.ReportMetric(float64(count), "objects/op")
			})
		})
	}
}
