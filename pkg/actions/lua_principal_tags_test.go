package actions_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/actions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/graveler"
)

func TestLuaHookPreservesPrincipalTagsInScriptAndAPIRequests(t *testing.T) {
	t.Parallel()
	user := &model.User{Username: "initiating-user"}
	wantTags := principaltags.Tags{"clr": "S", "Project": "Science"}
	ctx := auth.WithPrincipalTags(auth.WithUser(t.Context(), user), wantTags)
	var methods []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		gotUser, err := auth.GetUser(r.Context())
		require.NoError(t, err)
		require.Same(t, user, gotUser)
		gotTags, found := auth.PrincipalTagsFromContext(r.Context())
		require.True(t, found)
		require.Equal(t, wantTags, gotTags)
		switch r.Method {
		case http.MethodGet:
			require.Equal(t, "hooks/check.lua", r.URL.Query().Get("path"))
			_, err = w.Write([]byte(`local lakefs = require("lakefs")
local status = lakefs.create_tag("repo", "main", "reviewed")
assert(status == 201)`))
			require.NoError(t, err)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, err = w.Write([]byte(`{"id":"reviewed","commit_id":"commit"}`))
			require.NoError(t, err)
		default:
			t.Errorf("unexpected internal request: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})}
	collector := NewActionStatsMockCollector()
	hook, err := actions.NewLuaHook(actions.ActionHook{
		ID: "principal-tags", Type: actions.HookTypeLua,
		Properties: map[string]any{"script_path": "hooks/check.lua"},
	}, &actions.Action{}, actions.Config{Enabled: true}, server, "http://lakefs.example", &collector)
	require.NoError(t, err)
	var output bytes.Buffer
	err = hook.Run(ctx, graveler.HookRecord{
		Repository: &graveler.RepositoryRecord{
			RepositoryID: "repo",
			Repository:   &graveler.Repository{StorageNamespace: "local://test"},
		},
		SourceRef: "main",
	}, &output)
	require.NoError(t, err)
	require.Equal(t, []string{http.MethodGet, http.MethodPost}, methods)
}
