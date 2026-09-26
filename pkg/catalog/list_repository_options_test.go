package catalog_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func TestWithListReposPermissionFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		username    string
		policies    []*model.Policy
		testRepoIDs []string
		wantVisible []string
	}{
		{
			name:        "no policies filters all",
			username:    "user1",
			policies:    nil,
			testRepoIDs: []string{"repo1", "repo2", "repo3"},
			wantVisible: []string{},
		},
		{
			name:     "wildcard allows all",
			username: "user1",
			policies: []*model.Policy{{
				Statement: model.Statements{{
					Effect:   model.StatementEffectAllow,
					Action:   []string{"fs:*"},
					Resource: "*",
				}},
			}},
			testRepoIDs: []string{"repo1", "repo2", "repo3"},
			wantVisible: []string{"repo1", "repo2", "repo3"},
		},
		{
			name:     "pattern filters correctly",
			username: "user1",
			policies: []*model.Policy{{
				Statement: model.Statements{{
					Effect:   model.StatementEffectAllow,
					Action:   []string{"fs:ListRepositories"},
					Resource: "arn:lakefs:fs:::repository/analytics-*",
				}},
			}},
			testRepoIDs: []string{"analytics-prod", "analytics-dev", "other-repo"},
			wantVisible: []string{"analytics-prod", "analytics-dev"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := catalog.NewListRepositoriesOptions([]catalog.ListRepositoriesOptionsFunc{
				catalog.WithListReposPermissionFilter(tt.username, tt.policies, auth.NewConditionContext("")),
			})

			var visible []string
			for _, repoID := range tt.testRepoIDs {
				include, err := opts.FilterFunc(repoID)
				require.NoError(t, err)
				if include {
					visible = append(visible, repoID)
				}
			}

			if len(visible) != len(tt.wantVisible) {
				t.Errorf("visible repos count = %d, want %d", len(visible), len(tt.wantVisible))
				return
			}

			for i, v := range visible {
				if v != tt.wantVisible[i] {
					t.Errorf("visible[%d] = %s, want %s", i, v, tt.wantVisible[i])
				}
			}
		})
	}
}

func TestRepositoryPermissionFilterBindsRequestSnapshot(t *testing.T) {
	t.Parallel()
	conditionCtx := auth.NewConditionContextWithFields(map[string]string{"department": "blue"})
	conditionCtx.AddPrincipalTags(principaltags.Tags{"team": "blue"})
	policies := []*model.Policy{{Statement: model.Statements{
		{
			Effect: model.StatementEffectAllow, Action: []string{permissions.ListRepositoriesAction},
			Resource: "arn:lakefs:fs:::repository/${aws:PrincipalTag/team}-*",
			Condition: map[string]map[string][]string{
				"StringEquals": {"department": {"${aws:PrincipalTag/team}"}},
			},
		},
		{
			Effect: model.StatementEffectDeny, Action: []string{permissions.ListRepositoriesAction},
			Resource: "arn:lakefs:fs:::repository/${aws:PrincipalTag/team}-private",
		},
	}}}
	filter := catalog.WithListReposPermissionFilter("alice", policies, conditionCtx)
	firstPage := catalog.NewListRepositoriesOptions([]catalog.ListRepositoriesOptionsFunc{filter})

	// Changes after preparation must not change the request's decisions.
	conditionCtx.AddPrincipalTags(principaltags.Tags{"team": "red"})
	conditionCtx.Fields["department"] = "red"
	policies[0].Statement[0].Resource = "*"
	secondPage := catalog.NewListRepositoriesOptions([]catalog.ListRepositoriesOptionsFunc{filter})
	for _, opts := range []*catalog.ListRepositoriesOptions{firstPage, secondPage} {
		for _, tt := range []struct {
			repository string
			allowed    bool
		}{
			{"blue-project", true}, {"red-project", false}, {"blue-private", false}, {"blue-project", true},
		} {
			allowed, err := opts.FilterFunc(tt.repository)
			require.NoError(t, err)
			require.Equal(t, tt.allowed, allowed, tt.repository)
		}
	}
}

func TestRepositoryPermissionFilterKeepsPreparationError(t *testing.T) {
	t.Parallel()
	conditionCtx := auth.NewConditionContext("")
	conditionCtx.AddPrincipalTags(principaltags.Tags{"team": "*"})
	policies := []*model.Policy{{Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ListRepositoriesAction},
		Resource: "arn:lakefs:fs:::repository/${aws:PrincipalTag/team}",
	}}}}
	filter := catalog.WithListReposPermissionFilter("alice", policies, conditionCtx)
	firstPage := catalog.NewListRepositoriesOptions([]catalog.ListRepositoriesOptionsFunc{filter})
	conditionCtx.AddPrincipalTags(principaltags.Tags{"team": "blue"})
	policies[0].Statement[0].Resource = "*"
	secondPage := catalog.NewListRepositoriesOptions([]catalog.ListRepositoriesOptionsFunc{filter})
	for _, opts := range []*catalog.ListRepositoriesOptions{firstPage, secondPage} {
		for _, repository := range []string{"blue", "red"} {
			allowed, err := opts.FilterFunc(repository)
			require.False(t, allowed)
			require.ErrorIs(t, err, policytemplate.ErrWildcardValue)
		}
	}
}

func BenchmarkRepositoryPermissionFilter(b *testing.B) {
	conditionCtx := auth.NewConditionContext("")
	conditionCtx.AddPrincipalTags(principaltags.Tags{"team": "blue"})
	policies := []*model.Policy{{Statement: model.Statements{{
		Effect: model.StatementEffectAllow, Action: []string{permissions.ListRepositoriesAction},
		Resource: "arn:lakefs:fs:::repository/${aws:PrincipalTag/team}-*",
	}}}}
	b.Run("prepare_per_repository", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			allowed, err := auth.CheckPermission(permissions.RepoArn("blue-project"), "alice", policies, permissions.ListRepositoriesAction, conditionCtx)
			if err != nil || !allowed {
				b.Fatalf("CheckPermission() = %v, %v", allowed, err)
			}
		}
	})
	b.Run("shared_preparation", func(b *testing.B) {
		opts := catalog.NewListRepositoriesOptions([]catalog.ListRepositoriesOptionsFunc{
			catalog.WithListReposPermissionFilter("alice", policies, conditionCtx),
		})
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			allowed, err := opts.FilterFunc("blue-project")
			if err != nil || !allowed {
				b.Fatalf("FilterFunc() = %v, %v", allowed, err)
			}
		}
	})
}
