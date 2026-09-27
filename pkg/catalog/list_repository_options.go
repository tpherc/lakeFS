package catalog

import (
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/permissions"
)

// ListRepositoriesOptions controls list repositories request options
type ListRepositoriesOptions struct {
	// FilterFunc is an optional predicate that filters repositories.
	// Returns true if the repository should be included, or an error that stops listing.
	FilterFunc func(repoID string) (bool, error)
}

// ListRepositoriesOptionsFunc is a function that modifies ListRepositoriesOptions
type ListRepositoriesOptionsFunc func(opts *ListRepositoriesOptions)

// NewListRepositoriesOptions creates a new ListRepositoriesOptions from the given functions
func NewListRepositoriesOptions(opts []ListRepositoriesOptionsFunc) *ListRepositoriesOptions {
	options := &ListRepositoriesOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return options
}

// WithListReposPermissionFilter snapshots policies and attributes when the option is created.
// It filters repositories where the user has fs:ListRepositories permission.
func WithListReposPermissionFilter(username string, policies []*model.Policy, conditionCtx *auth.ConditionContext) ListRepositoriesOptionsFunc {
	checker, err := auth.PreparePermissionChecker(username, policies, conditionCtx)
	return func(opts *ListRepositoriesOptions) {
		opts.FilterFunc = func(repoID string) (bool, error) {
			if err != nil {
				return false, err
			}
			return checker.Check(permissions.RepoArn(repoID), permissions.ListRepositoriesAction)
		}
	}
}
