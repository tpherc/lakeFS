package catalog

import (
	"context"

	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/permissions"
)

// WithDiffPermissionFilter uses the request's authorizer for every participating
// object version. A change is visible only when all required versions are readable.
func WithDiffPermissionFilter(ctx context.Context, authorizer auth.Authorizer, username, repository, clientIP string) DiffOptionsFunc {
	return WithDiffFilter(func(diff *EntryDiff) (bool, error) {
		entries, err := readableDiffEntries(diff)
		if err != nil {
			return false, err
		}
		perms := permissions.Node{Type: permissions.NodeTypeAnd, Nodes: make([]permissions.Node, 0, len(entries))}
		for _, entry := range entries {
			if entry == nil {
				continue // an absent conflict side does not describe an object
			}
			perms.Nodes = append(perms.Nodes, permissions.Node{Permission: permissions.Permission{
				Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn(repository, diff.Path.String()),
				ObjectMetadata: entry.Metadata,
			}})
		}
		return authorizeEntryVisibility(ctx, authorizer, &auth.AuthorizationRequest{
			Username: username, ClientIP: clientIP, RequiredPermissions: perms,
		})
	})
}

func readableDiffEntries(diff *EntryDiff) ([]*Entry, error) {
	switch diff.Type {
	case graveler.DiffTypeAdded:
		if diff.Entry != nil && diff.LeftEntry == nil {
			return []*Entry{diff.Entry}, nil
		}
	case graveler.DiffTypeRemoved:
		if diff.LeftEntry != nil {
			return []*Entry{diff.LeftEntry}, nil
		}
	case graveler.DiffTypeChanged:
		if diff.LeftEntry != nil && diff.Entry != nil {
			return []*Entry{diff.LeftEntry, diff.Entry}, nil
		}
	case graveler.DiffTypeConflict:
		// Producers validate side presence before changing the type to conflict.
		// A deletion conflict's legacy Entry repeats its existing left side.
		if diff.LeftEntry != nil || diff.Entry != nil {
			return []*Entry{diff.LeftEntry, diff.Entry, diff.BaseEntry}, nil
		}
	default:
		return nil, ErrUnknownDiffType
	}
	return nil, ErrMissingDiffEntry
}
