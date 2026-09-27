package catalog

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
)

func TestRunBackgroundTaskStepsPreservesPrincipalSnapshot(t *testing.T) {
	t.Parallel()
	for _, tagged := range []bool{false, true} {
		t.Run(map[bool]string{false: "tagless", true: "tagged"}[tagged], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store, catalog, repository := setupTaskTest(t)
				user := &model.User{Username: "initiating-user"}
				var tags principaltags.Tags
				if tagged {
					tags = principaltags.Tags{"clr": "S", "Project": "Science"}
				}
				ctx, cancel := context.WithCancel(auth.WithPrincipalTags(auth.WithUser(t.Context(), user), tags))
				defer cancel()
				ready := make(chan struct{})
				observed := make(chan context.Context, 1)
				steps := []TaskStep{{
					Name: "observe principal",
					Func: func(ctx context.Context) error {
						<-ready
						observed <- ctx
						return nil
					},
				}}
				taskID := NewTaskID("TEST")
				err := catalog.RunBackgroundTaskSteps(ctx, repository, OpDumpRefs, taskID, steps, &TaskMsg{})
				cancel()
				if tagged {
					tags["clr"] = "Changed"
				}
				close(ready)
				require.NoError(t, err)
				synctest.Wait()
				var taskCtx context.Context
				select {
				case taskCtx = <-observed:
				default:
					t.Fatal("background step did not run")
				}
				require.NoError(t, taskCtx.Err(), "task must outlive the originating request")
				gotUser, err := auth.GetUser(taskCtx)
				require.NoError(t, err)
				require.Same(t, user, gotUser)
				gotTags, found := auth.PrincipalTagsFromContext(taskCtx)
				require.True(t, found, "tagless principals also carry an explicit snapshot")
				if tagged {
					require.Equal(t, principaltags.Tags{"clr": "S", "Project": "Science"}, gotTags)
				} else {
					require.Empty(t, gotTags)
				}
				var status TaskMsg
				_, err = GetTaskStatus(t.Context(), store, repository, taskID, &status)
				require.NoError(t, err)
				require.True(t, status.Task.Done)
			})
		})
	}
}
