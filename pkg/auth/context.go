package auth

import (
	"context"
	"maps"

	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
)

type contextKey string

const (
	userContextKey          contextKey = "user"
	principalTagsContextKey contextKey = "principal_tags"
)

func GetUser(ctx context.Context) (*model.User, error) {
	user, ok := ctx.Value(userContextKey).(*model.User)
	if !ok || user == nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// WithUser establishes a principal without inheriting another principal's tags.
// Use CopyAuthorizationContext when continuing work as the same principal.
func WithUser(ctx context.Context, user *model.User) context.Context {
	return context.WithValue(WithPrincipalTags(ctx, nil), userContextKey, user)
}

// WithoutUser removes any authenticated user from the context.
func WithoutUser(ctx context.Context) context.Context {
	return WithUser(ctx, nil)
}

// CopyUserFromContext copies the user alone, clearing tags when replacing it.
// Use CopyAuthorizationContext to preserve the complete initiating principal.
func CopyUserFromContext(srcCtx, dstCtx context.Context) context.Context {
	if user, _ := GetUser(srcCtx); user != nil {
		return WithUser(dstCtx, user)
	}
	return dstCtx
}

// WithPrincipalTags attaches a snapshot, including an explicitly empty snapshot.
func WithPrincipalTags(ctx context.Context, tags principaltags.Tags) context.Context {
	return context.WithValue(ctx, principalTagsContextKey, maps.Clone(tags))
}

// PrincipalTagsFromContext returns a copy so callers cannot change the principal.
func PrincipalTagsFromContext(ctx context.Context) (principaltags.Tags, bool) {
	tags, ok := ctx.Value(principalTagsContextKey).(principaltags.Tags)
	return maps.Clone(tags), ok
}

// CopyAuthorizationContext carries one principal snapshot onto a new lifetime.
// An unauthenticated source also clears any principal inherited from dst.
func CopyAuthorizationContext(src, dst context.Context) context.Context {
	user, err := GetUser(src)
	if err != nil {
		return WithoutUser(dst)
	}
	tags, _ := PrincipalTagsFromContext(src)
	return WithPrincipalTags(WithUser(dst, user), tags)
}
