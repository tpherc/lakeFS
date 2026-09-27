package actions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/graveler"
)

func TestAsyncRunPreservesPrincipalSnapshot(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		t.Run(map[bool]string{false: "tagless", true: "tagged"}[tagged], func(t *testing.T) {
			var tags principaltags.Tags
			if tagged {
				tags = principaltags.Tags{"clr": "S"}
			}
			user := &model.User{Username: "initiator"}
			requestCtx, cancel := context.WithCancel(auth.WithPrincipalTags(auth.WithUser(t.Context(), user), tags))
			serviceCtx := auth.WithPrincipalTags(auth.WithUser(t.Context(), &model.User{Username: "service"}), principaltags.Tags{"service": "private"})
			source := &principalSnapshotSource{observed: make(chan context.Context, 1), ready: make(chan struct{})}
			service := &StoreService{ctx: serviceCtx, Source: source, cfg: Config{Enabled: true}}
			service.asyncRun(requestCtx, graveler.HookRecord{})
			cancel()
			if tagged {
				tags["clr"] = "changed"
			}
			close(source.ready)
			service.wg.Wait()
			ctx := <-source.observed
			require.NoError(t, ctx.Err(), "hook uses service lifetime")
			gotUser, err := auth.GetUser(ctx)
			require.NoError(t, err)
			require.Same(t, user, gotUser)
			got, found := auth.PrincipalTagsFromContext(ctx)
			require.True(t, found)
			if tagged {
				require.Equal(t, principaltags.Tags{"clr": "S"}, got)
			} else {
				require.Empty(t, got)
			}
		})
	}
}

type principalSnapshotSource struct {
	Source
	observed chan context.Context
	ready    chan struct{}
}

func (s *principalSnapshotSource) List(ctx context.Context, _ graveler.HookRecord) ([]string, error) {
	<-s.ready
	s.observed <- ctx
	return nil, nil
}
