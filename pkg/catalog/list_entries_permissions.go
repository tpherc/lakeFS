package catalog

import (
	"context"
	"errors"

	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/permissions"
)

// WithListEntriesPermissionFilter checks stored object metadata with the same
// prepared authorizer used for the request's initial list permission. Filtering
// precedes directory grouping, so a prefix requires a readable descendant.
func WithListEntriesPermissionFilter(ctx context.Context, authorizer auth.Authorizer, username, repository, clientIP string) ListEntriesOptionsFunc {
	return WithEntryFilter(func(entry *DBEntry) (bool, error) {
		response, err := authorizer.Authorize(ctx, &auth.AuthorizationRequest{
			Username: username,
			ClientIP: clientIP,
			RequiredPermissions: permissions.Node{Permission: permissions.Permission{
				Action:         permissions.ReadObjectAction,
				Resource:       permissions.ObjectArn(repository, entry.Path),
				ObjectMetadata: entry.Metadata,
			}},
		})
		if err != nil {
			return false, err
		}
		if response == nil {
			return false, auth.ErrInvalidRequest
		}
		if response.Error != nil && !errors.Is(response.Error, auth.ErrInsufficientPermissions) {
			return false, response.Error
		}
		return response.Allowed && response.Error == nil, nil
	})
}
