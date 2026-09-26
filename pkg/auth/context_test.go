package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
)

func TestPrincipalTagsContextSnapshots(t *testing.T) {
	tags := principaltags.Tags{"Project": "original"}
	ctx := auth.WithPrincipalTags(t.Context(), tags)
	tags["Project"] = "changed input"
	got, found := auth.PrincipalTagsFromContext(ctx)
	require.True(t, found)
	require.Equal(t, "original", got["Project"])
	got["Project"] = "changed output"
	got, found = auth.PrincipalTagsFromContext(ctx)
	require.True(t, found)
	require.Equal(t, "original", got["Project"])
	for _, empty := range []principaltags.Tags{nil, {}} {
		cleared, found := auth.PrincipalTagsFromContext(auth.WithPrincipalTags(ctx, empty))
		require.True(t, found)
		require.Empty(t, cleared)
	}
	_, found = auth.PrincipalTagsFromContext(t.Context())
	require.False(t, found)
}

func TestPrincipalReplacementClearsTags(t *testing.T) {
	first := &model.User{Username: "first"}
	second := &model.User{Username: "second"}
	ctx := auth.WithPrincipalTags(auth.WithUser(t.Context(), first), principaltags.Tags{"clr": "S"})
	for _, user := range []*model.User{first, second, nil} {
		replaced := auth.WithUser(ctx, user)
		tags, found := auth.PrincipalTagsFromContext(replaced)
		require.True(t, found)
		require.Empty(t, tags)
		got, err := auth.GetUser(replaced)
		if user == nil {
			require.ErrorIs(t, err, auth.ErrUserNotFound)
		} else {
			require.NoError(t, err)
			require.Same(t, user, got)
		}
	}
	cleared := auth.WithoutUser(ctx)
	_, err := auth.GetUser(cleared)
	require.ErrorIs(t, err, auth.ErrUserNotFound)
	tags, found := auth.PrincipalTagsFromContext(cleared)
	require.True(t, found)
	require.Empty(t, tags)
}

func TestCopyAuthorizationContext(t *testing.T) {
	user := &model.User{Username: "initiator"}
	destinationUser := &model.User{Username: "service"}
	destination := auth.WithPrincipalTags(auth.WithUser(t.Context(), destinationUser), principaltags.Tags{"service": "private"})
	source, cancel := context.WithCancel(auth.WithPrincipalTags(auth.WithUser(t.Context(), user), principaltags.Tags{"clr": "S"}))
	copied := auth.CopyAuthorizationContext(source, destination)
	cancel()
	require.NoError(t, copied.Err())
	got, err := auth.GetUser(copied)
	require.NoError(t, err)
	require.Same(t, user, got)
	tags, found := auth.PrincipalTagsFromContext(copied)
	require.True(t, found)
	require.Equal(t, principaltags.Tags{"clr": "S"}, tags)
	tags["clr"] = "changed"
	original, _ := auth.PrincipalTagsFromContext(source)
	require.Equal(t, "S", original["clr"])
	for _, source := range []context.Context{t.Context(), auth.WithUser(t.Context(), user)} {
		cleared := auth.CopyAuthorizationContext(source, destination)
		tags, found := auth.PrincipalTagsFromContext(cleared)
		require.True(t, found)
		require.Empty(t, tags)
	}
	cleared := auth.CopyAuthorizationContext(t.Context(), destination)
	_, err = auth.GetUser(cleared)
	require.ErrorIs(t, err, auth.ErrUserNotFound)
}
