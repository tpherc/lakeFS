package lakefs

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
)

func TestInternalRequestPrincipalTags(t *testing.T) {
	t.Parallel()
	initiating := &model.User{Username: "initiator"}
	tags := principaltags.Tags{"clr": "S"}
	ctx := auth.WithPrincipalTags(auth.WithUser(t.Context(), initiating), tags)
	for _, user := range []*model.User{initiating, {Username: "service"}, {Username: "initiator"}} {
		request, err := newLakeFSRequest(ctx, user, http.MethodGet, "/repositories", nil)
		require.NoError(t, err)
		gotUser, err := auth.GetUser(request.Context())
		require.NoError(t, err)
		require.Same(t, user, gotUser)
		gotTags, found := auth.PrincipalTagsFromContext(request.Context())
		require.True(t, found)
		if user == initiating {
			require.Equal(t, tags, gotTags)
			gotTags["clr"] = "changed"
		} else {
			require.Empty(t, gotTags, "even a replacement user with the same name needs its own attributes")
		}
		require.Nil(t, request.Context().Value(chi.RouteCtxKey))
	}
	original, _ := auth.PrincipalTagsFromContext(ctx)
	require.Equal(t, tags, original)
}
