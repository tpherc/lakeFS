package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/api/apiutil"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	authparams "github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
)

type diffFilterAuth struct {
	auth.Service
	policyLoads     int
	readPermissions int
	afterFirstRead  func()
	prepareErr      error
	readAuthorizer  func(context.Context, *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error)
}

func (s *diffFilterAuth) ListEffectivePolicies(ctx context.Context, username string, params *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	s.policyLoads++
	if s.prepareErr != nil {
		return nil, nil, s.prepareErr
	}
	return s.Service.ListEffectivePolicies(ctx, username, params)
}

func diffReadLeaves(node permissions.Node) int {
	if node.Type == permissions.NodeTypeNode {
		if node.Permission.Action == permissions.ReadObjectAction {
			return 1
		}
		return 0
	}
	count := 0
	for _, child := range node.Nodes {
		count += diffReadLeaves(child)
	}
	return count
}

func (s *diffFilterAuth) Authorize(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	if _, err := auth.AuthorizationPolicies(ctx, req, s.ListEffectivePolicies); err != nil && !errors.Is(err, auth.ErrNotImplemented) {
		return nil, err
	}

	count := diffReadLeaves(req.RequiredPermissions)
	s.readPermissions += count
	if count > 0 && s.readAuthorizer != nil {
		return s.readAuthorizer(ctx, req)
	}
	response, err := s.Service.Authorize(ctx, req)
	if count > 0 && s.afterFirstRead != nil {
		callback := s.afterFirstRead
		s.afterFirstRead = nil
		callback()
	}
	return response, err
}

type diffFilterFixture struct {
	*filteredListingFixture
	authorizer *diffFilterAuth
	mode       string
	right      string
}

func newDiffFilterFixture(t *testing.T, mode string) *diffFilterFixture {
	t.Helper()
	listing := newFilteredListingFixture(t)
	authorizer := &diffFilterAuth{Service: listing.auth.Service}
	listing.controller.Auth = authorizer
	return &diffFilterFixture{filteredListingFixture: listing, authorizer: authorizer, mode: mode, right: "main"}
}

func (f *diffFilterFixture) put(t *testing.T, branch, path, classification, revision string) {
	t.Helper()
	metadata := catalog.Metadata{"revision": revision}
	if classification != "" {
		metadata["dcs:cls"] = classification
	}
	require.NoError(t, f.controller.Catalog.CreateEntry(t.Context(), f.repository, branch, catalog.DBEntry{
		Path: path, PhysicalAddress: path + revision, AddressType: catalog.AddressTypeRelative,
		Size: int64(len(path) + len(revision)), Checksum: path + "-" + revision, ContentType: "text/plain",
		CreationDate: time.Unix(1700000000, 0), Metadata: metadata,
	}))
}

func (f *diffFilterFixture) commit(t *testing.T, branch string) string {
	t.Helper()
	commit, err := f.controller.Catalog.Commit(t.Context(), f.repository, branch, "diff test", f.user.Username, nil, nil, nil, true)
	require.NoError(t, err)
	return commit.Reference
}

func (f *diffFilterFixture) startChanges(t *testing.T) {
	t.Helper()
	f.commit(t, "main")
	if f.mode != "branch" {
		f.right = "changes"
		_, err := f.controller.Catalog.CreateBranch(t.Context(), f.repository, f.right, "main")
		require.NoError(t, err)
	}
}

func (f *diffFilterFixture) finishChanges(t *testing.T) {
	t.Helper()
	if f.mode != "branch" {
		f.commit(t, f.right)
	}
}

func (f *diffFilterFixture) request(t *testing.T, clearance string) *http.Request {
	t.Helper()
	tags := principaltags.Tags{}
	if clearance != "" {
		tags["clr"] = clearance
	}
	ctx := auth.WithPrincipalTags(auth.WithUser(t.Context(), f.user), tags)
	return httptest.NewRequest(http.MethodGet, "http://lakefs.example/", nil).WithContext(ctx)
}

func (f *diffFilterFixture) diff(t *testing.T, request *http.Request, params apigen.DiffRefsParams) (*httptest.ResponseRecorder, apigen.DiffList) {
	t.Helper()
	recorder := httptest.NewRecorder()
	if f.mode == "branch" {
		f.controller.DiffBranch(recorder, request, f.repository, f.right, apigen.DiffBranchParams{After: params.After, Amount: params.Amount, Prefix: params.Prefix, Delimiter: params.Delimiter})
	} else {
		if f.mode != "default" {
			params.Type = &f.mode
		}
		f.controller.DiffRefs(recorder, request, f.repository, "main", f.right, params)
	}
	var result apigen.DiffList
	if recorder.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
	}
	return recorder, result
}

func diffPaths(result apigen.DiffList) []string {
	paths := make([]string, 0, len(result.Results))
	for _, row := range result.Results {
		paths = append(paths, row.Path)
	}
	return paths
}

func TestDiffFilteredHidesUnreadableAdditions(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiffFilterFixture(t, mode)
			f.startChanges(t)
			f.put(t, f.right, "hidden-secret", "TS", "private")
			f.put(t, f.right, "visible", "U", "public")
			f.finishChanges(t)
			recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, []string{"visible"}, diffPaths(result))
			require.NotContains(t, recorder.Body.String(), "hidden-secret")
			require.NotContains(t, recorder.Body.String(), "private")
			require.Equal(t, 1, f.authorizer.policyLoads)
		})
	}
}

func TestDiffFilteredRequiresReadableHistoricalVersions(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		t.Run(mode, func(t *testing.T) {
			testDiffFilteredHistoricalVersions(t, mode)
		})
	}
}

func testDiffFilteredHistoricalVersions(t *testing.T, mode string) {
	t.Helper()
	f := newDiffFilterFixture(t, mode)
	for _, initial := range []struct{ path, class string }{
		{"removed-u", "U"}, {"removed-ts", "TS"}, {"changed-uu", "U"},
		{"upgrade", "U"}, {"downgrade", "TS"}, {"changed-ts", "TS"},
	} {
		f.put(t, "main", initial.path, initial.class, "old")
	}
	f.startChanges(t)
	for _, path := range []string{"removed-u", "removed-ts"} {
		require.NoError(t, f.controller.Catalog.DeleteEntry(t.Context(), f.repository, f.right, path))
	}
	f.put(t, f.right, "added-u", "U", "new")
	f.put(t, f.right, "added-ts", "TS", "new")
	f.put(t, f.right, "changed-uu", "U", "new")
	f.put(t, f.right, "changed-ts", "TS", "new")
	// Classification is the only changed field on these two objects.
	f.put(t, f.right, "upgrade", "TS", "old")
	f.put(t, f.right, "downgrade", "U", "old")
	f.finishChanges(t)
	for _, stats := range []bool{false, true} {
		recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{IncludeRightStats: &stats})
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		require.Equal(t, []string{"added-u", "changed-uu", "removed-u"}, diffPaths(result))
		require.False(t, result.Pagination.HasMore)
		require.Equal(t, []string{"added", "changed", "removed"}, []string{result.Results[0].Type, result.Results[1].Type, result.Results[2].Type})
		requireDiffHistoricalStats(t, result.Results, mode != "branch" && stats)
		for _, hidden := range []string{"added-ts", "changed-ts", "removed-ts", "upgrade", "downgrade"} {
			require.NotContains(t, recorder.Body.String(), hidden)
		}
	}
	recorder, result := f.diff(t, f.request(t, "TS"), apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Len(t, result.Results, 8, "fully readable callers retain every legacy diff row")
	require.Equal(t, 3, f.authorizer.policyLoads)
	// Each request supplies read permission leaves for two additions, two
	// deletions and both sides of four changes; IAM may short-circuit denials.
	require.Equal(t, 36, f.authorizer.readPermissions)
}

func TestDiffFilteredPaginationAndDirectories(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		t.Run(mode, func(t *testing.T) {
			testDiffFilteredPagination(t, mode)
		})
	}
}

func testDiffFilteredPagination(t *testing.T, mode string) {
	t.Helper()
	f := newDiffFilterFixture(t, mode)
	f.startChanges(t)
	for _, object := range []struct{ path, class string }{
		{"a-hidden/file", "TS"}, {"b-mixed/1-hidden", "TS"}, {"b-mixed/2-visible", "U"},
		{"b-mixed/3-visible", "U"}, {"c-hidden", "TS"}, {"d-visible", "U"}, {"z-hidden", "TS"},
	} {
		f.put(t, f.right, object.path, object.class, "new")
	}
	f.finishChanges(t)
	for _, delimiter := range []apigen.PaginationDelimiter{"", "/"} {
		params := apigen.DiffRefsParams{Amount: apiutil.Ptr(apigen.PaginationAmount(1)), Delimiter: &delimiter, IncludeRightStats: swag.Bool(true)}
		expected := []string{"b-mixed/2-visible", "b-mixed/3-visible", "d-visible"}
		if delimiter == "/" {
			expected = []string{"b-mixed/", "d-visible"}
		}
		for index, path := range expected {
			recorder, result := f.diff(t, f.request(t, "U"), params)
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, []string{path}, diffPaths(result))
			require.Equal(t, index+1 < len(expected), result.Pagination.HasMore)
			if result.Pagination.HasMore {
				require.Equal(t, path, result.Pagination.NextOffset)
				after := apigen.PaginationAfter(result.Pagination.NextOffset)
				params.After = &after
			} else {
				require.Empty(t, result.Pagination.NextOffset)
			}
			if delimiter == "/" && index == 0 {
				require.Nil(t, result.Results[0].Right)
				require.Nil(t, result.Results[0].SizeBytes)
			}
		}
	}
	prefix := apigen.PaginationPrefix("a-hidden/")
	recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{Prefix: &prefix})
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Empty(t, result.Results)
	require.False(t, result.Pagination.HasMore)
}

func TestDiffFilteredConditionsAndMissingAttributes(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiffFilterFixture(t, mode)
			f.startChanges(t)
			f.put(t, f.right, "U/visible", "U", "new")
			f.put(t, f.right, "U/explicit-deny", "U", "new")
			f.put(t, f.right, "U/no-metadata", "", "new")
			f.put(t, f.right, "U/wrong-metadata", "TS", "new")
			f.put(t, f.right, "TS/wrong-path", "U", "new")
			f.finishChanges(t)
			f.setPolicy(t, model.Statements{
				{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction}, Resource: "*"},
				{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn(f.repository, "${aws:PrincipalTag/clr}/*"),
					Condition: map[string]map[string][]string{"StringEquals": {"lakefs:ObjectMetadata/dcs:cls": {"${aws:PrincipalTag/clr}"}}}},
				{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn(f.repository, "U/explicit-deny")},
				{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: "*",
					Condition: map[string]map[string][]string{"Null": {"lakefs:ObjectMetadata/dcs:cls": {"true"}}}},
			})
			for _, clearance := range []string{"U", "", "unknown"} {
				recorder, result := f.diff(t, f.request(t, clearance), apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
				require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				if clearance == "U" {
					require.Equal(t, []string{"U/visible"}, diffPaths(result))
				} else {
					require.Empty(t, result.Results)
				}
			}
			// Null must also work without a positive metadata condition hiding missing entries first.
			f.setPolicy(t, model.Statements{
				{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction, permissions.ReadObjectAction}, Resource: "*"},
				{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: "*",
					Condition: map[string]map[string][]string{"Null": {"lakefs:ObjectMetadata/dcs:cls": {"true"}}}},
			})
			recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Len(t, result.Results, 4)
			require.NotContains(t, recorder.Body.String(), "U/no-metadata")
		})
	}
}

func TestDiffFilteredSnapshotChangesAtNextRequest(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiffFilterFixture(t, mode)
			f.startChanges(t)
			f.put(t, f.right, "a", "U", "new")
			f.put(t, f.right, "b", "U", "new")
			f.finishChanges(t)
			request := f.request(t, "U")
			f.authorizer.afterFirstRead = func() {
				f.setPolicy(t, model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction}, Resource: "*"}})
				// Replacing the caller context cannot change the in-flight principal snapshot.
				request = request.WithContext(auth.WithPrincipalTags(request.Context(), principaltags.Tags{"clr": "unknown"}))
			}
			recorder, result := f.diff(t, request, apigen.DiffRefsParams{Amount: apiutil.Ptr(apigen.PaginationAmount(1))})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, []string{"a"}, diffPaths(result))
			require.True(t, result.Pagination.HasMore, "lookahead uses the original policy snapshot")
			require.Equal(t, 1, f.authorizer.policyLoads)
			after := apigen.PaginationAfter(result.Pagination.NextOffset)
			recorder, result = f.diff(t, request, apigen.DiffRefsParams{After: &after})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Empty(t, result.Results)
			require.False(t, result.Pagination.HasMore)
			require.Equal(t, 2, f.authorizer.policyLoads)
		})
	}
}

func TestDiffFilteredKeepsComparedEntryAfterReplacement(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiffFilterFixture(t, mode)
			f.startChanges(t)
			f.put(t, f.right, "visible", "U", "captured")
			f.finishChanges(t)
			f.authorizer.afterFirstRead = func() { f.put(t, f.right, "visible", "TS", "replacement") }
			store := &metadataLookupStore{Store: f.controller.Catalog.Store}
			f.controller.Catalog.Store = store
			recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, []string{"visible"}, diffPaths(result))
			require.Zero(t, store.lookups, "diff authorization must not load a live object path")
			require.NotContains(t, recorder.Body.String(), "replacement")
			if mode != "branch" {
				require.Equal(t, "U", result.Results[0].Right.Metadata.AdditionalProperties["dcs:cls"])
				require.Equal(t, "visible-captured", result.Results[0].Right.Checksum)
			}
		})
	}
}

func TestDiffFilteredConflictsRequireEveryExistingVersion(t *testing.T) {
	for _, mode := range []string{"three_dot", "default"} {
		for _, conflict := range []string{"add-add", "modify-modify", "modify-delete", "delete-modify"} {
			for _, hiddenSide := range []string{"none", "destination", "source", "base"} {
				if conflict == "add-add" && hiddenSide == "base" || conflict == "modify-delete" && hiddenSide == "source" || conflict == "delete-modify" && hiddenSide == "destination" {
					continue
				}
				t.Run(mode+"/"+conflict+"/hidden="+hiddenSide, func(t *testing.T) {
					testDiffFilteredConflict(t, mode, conflict, hiddenSide)
				})
			}
		}
	}
}

func testDiffFilteredConflict(t *testing.T, mode, conflict, hiddenSide string) {
	t.Helper()
	f := newDiffFilterFixture(t, mode)
	class := func(side string) string {
		if side == hiddenSide {
			return "TS"
		}
		return "U"
	}
	if conflict != "add-add" {
		f.put(t, "main", "conflict", class("base"), "base")
	}
	f.startChanges(t)
	if conflict == "delete-modify" {
		require.NoError(t, f.controller.Catalog.DeleteEntry(t.Context(), f.repository, "main", "conflict"))
	} else {
		f.put(t, "main", "conflict", class("destination"), "destination")
	}
	if conflict == "modify-delete" {
		require.NoError(t, f.controller.Catalog.DeleteEntry(t.Context(), f.repository, f.right, "conflict"))
	} else {
		f.put(t, f.right, "conflict", class("source"), "source")
	}
	f.commit(t, "main")
	f.finishChanges(t)
	for _, stats := range []bool{false, true} {
		recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{IncludeRightStats: &stats})
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		if hiddenSide == "none" {
			require.Equal(t, []string{"conflict"}, diffPaths(result))
			require.Equal(t, "conflict", result.Results[0].Type)
		} else {
			require.Empty(t, result.Results)
			require.NotContains(t, recorder.Body.String(), "conflict")
			require.NotContains(t, recorder.Body.String(), "checksum")
		}
	}
	recorder, result := f.diff(t, f.request(t, "TS"), apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, []string{"conflict"}, diffPaths(result))
	require.Equal(t, "conflict", result.Results[0].Type)
	revision := "source"
	if conflict == "modify-delete" {
		revision = "destination"
	}
	require.Equal(t, "conflict-"+revision, result.Results[0].Right.Checksum, "deletion conflicts retain the legacy destination stats")
	require.Equal(t, 3, f.authorizer.policyLoads)
	require.LessOrEqual(t, f.authorizer.readPermissions, 9, "at most three version permission leaves per conflict and request")
}

func TestDiffFilteredFailuresBeforeCatalog(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		for _, failure := range []string{"no user", "snapshot unavailable", "list denied"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				f := newDiffFilterFixture(t, mode)
				f.startChanges(t)
				f.put(t, f.right, "visible", "U", "new")
				f.finishChanges(t)
				request := f.request(t, "U")
				expectedStatus := http.StatusUnauthorized
				expectedLoads := 1
				switch failure {
				case "no user":
					request = request.WithContext(t.Context())
					expectedLoads = 0
				case "snapshot unavailable":
					f.authorizer.prepareErr = errors.New("test policy store unavailable")
					expectedStatus = http.StatusInternalServerError
				case "list denied":
					f.setPolicy(t, model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*"}})
				}
				store := &listPresignStore{Store: f.controller.Catalog.Store}
				f.controller.Catalog.Store = store
				recorder, _ := f.diff(t, request, apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
				require.Equal(t, expectedStatus, recorder.Code, recorder.Body.String())
				require.Equal(t, expectedLoads, f.authorizer.policyLoads)
				require.Zero(t, f.authorizer.readPermissions)
				require.Zero(t, store.repositoryLookups)
				require.NotContains(t, recorder.Body.String(), "visible")
			})
		}
	}
}

func TestDiffFilteredLookaheadAuthorizationFailureIsNotPartial(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		for _, failure := range []string{"error", "nil response", "unexpected response error"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				testDiffFilteredLookaheadFailure(t, mode, failure)
			})
		}
	}
}

func testDiffFilteredLookaheadFailure(t *testing.T, mode, failure string) {
	t.Helper()
	f := newDiffFilterFixture(t, mode)
	f.startChanges(t)
	f.put(t, f.right, "first-visible", "U", "private-stats")
	f.put(t, f.right, "second-visible", "U", "private-stats")
	f.finishChanges(t)
	f.authorizer.readAuthorizer = func(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
		if f.authorizer.readPermissions == 1 {
			return f.authorizer.Service.Authorize(ctx, req)
		}
		switch failure {
		case "error":
			return nil, errors.New("test authorizer unavailable")
		case "nil response":
			return nil, nil
		default:
			return &auth.AuthorizationResponse{Allowed: true, Error: errors.New("test unexpected authorization response")}, nil
		}
	}
	recorder, _ := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{Amount: apiutil.Ptr(apigen.PaginationAmount(1)), IncludeRightStats: swag.Bool(true)})
	expectedStatus := http.StatusInternalServerError
	if failure == "nil response" {
		expectedStatus = http.StatusBadRequest
	}
	require.Equal(t, expectedStatus, recorder.Code, recorder.Body.String())
	require.NotContains(t, recorder.Body.String(), "first-visible")
	require.NotContains(t, recorder.Body.String(), "private-stats")
	require.NotContains(t, recorder.Body.String(), "pagination")
	require.Equal(t, 2, f.authorizer.readPermissions)
	require.Equal(t, 1, f.authorizer.policyLoads)
}

func TestDiffFilteredBasicAuthFallback(t *testing.T) {
	for _, mode := range []string{"branch", "two_dot", "three_dot", "default"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiffFilterFixture(t, mode)
			f.startChanges(t)
			f.put(t, f.right, "first", "U", "new")
			f.put(t, f.right, "second", "TS", "new")
			f.finishChanges(t)
			basic := auth.NewBasicAuthService(kvtest.GetStore(t.Context(), t), crypt.NewSecretStore([]byte("diff-basic-auth-secret")), authparams.ServiceCache{}, logging.Dummy())
			_, err := basic.CreateUser(t.Context(), &model.User{Username: f.user.Username})
			require.NoError(t, err)
			f.authorizer.Service = basic
			recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, []string{"first", "second"}, diffPaths(result))
			require.Equal(t, 4, f.authorizer.policyLoads, "unsupported preparation preserves the BasicAuth gate and per-row authorizer")
			require.Equal(t, 2, f.authorizer.readPermissions)
		})
	}
}

func TestDiffFilteredCompactedDirectoryPagination(t *testing.T) {
	for _, staged := range []bool{false, true} {
		name := "only compacted"
		if staged {
			name = "compacted and staged"
		}
		t.Run(name, func(t *testing.T) {
			testDiffFilteredCompactedPagination(t, staged)
		})
	}
}

type compactedDiffRefManager struct {
	graveler.RefManager
	compacted graveler.MetaRangeID
}

func testDiffFilteredCompactedPagination(t *testing.T, staged bool) {
	t.Helper()
	f := newDiffFilterFixture(t, "branch")
	base := f.commit(t, "main")
	for _, object := range []struct{ path, class string }{
		{"a-dir/1-visible", "U"}, {"a-dir/2-hidden", "TS"}, {"b-hidden/file", "TS"},
		{"c-dir/1-visible", "U"}, {"z-last", "U"},
	} {
		f.put(t, "main", object.path, object.class, "compacted")
	}
	compacted := f.commit(t, "main")
	// Materialize real SSTs and retain the fresh staging token. The public
	// ref manager cannot serialize the private compaction attribute;
	// supply only that attribute through a wrapper during the read.
	store := f.controller.Catalog.Store.(*graveler.Graveler)
	repository, err := store.GetRepository(t.Context(), graveler.RepositoryID(f.repository))
	require.NoError(t, err)
	tree, err := store.GetCommit(t.Context(), repository, graveler.CommitID(compacted))
	require.NoError(t, err)
	branch, err := store.GetBranch(t.Context(), repository, "main")
	require.NoError(t, err)
	branch.CommitID = graveler.CommitID(base)
	require.NoError(t, store.RefManager.SetBranch(t.Context(), repository, "main", *branch))
	if staged {
		f.put(t, "main", "a-dir/0-staged", "U", "staged")
		f.put(t, "main", "c-dir/0-staged", "U", "staged")
		f.put(t, "main", "d-hidden/file", "TS", "staged")
	}
	// Post-commit Actions may still read the original store.
	readStore := *store
	readStore.RefManager = &compactedDiffRefManager{RefManager: store.RefManager, compacted: tree.MetaRangeID}
	f.controller.Catalog = &catalog.Catalog{Store: &readStore}
	actual, err := readStore.GetBranch(t.Context(), repository, "main")
	require.NoError(t, err)
	require.NotEmpty(t, actual.CompactedBaseMetaRangeID)
	delimiter := apigen.PaginationDelimiter("/")
	params := apigen.DiffRefsParams{Amount: apiutil.Ptr(apigen.PaginationAmount(1)), Delimiter: &delimiter}
	for index, expected := range []string{"a-dir/", "c-dir/", "z-last"} {
		recorder, result := f.diff(t, f.request(t, "U"), params)
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		require.Equal(t, []string{expected}, diffPaths(result))
		require.Equal(t, index < 2, result.Pagination.HasMore)
		if result.Pagination.HasMore {
			after := apigen.PaginationAfter(result.Pagination.NextOffset)
			params.After = &after
		}
	}
	require.Equal(t, 3, f.authorizer.policyLoads)
}

func (m *compactedDiffRefManager) GetBranch(ctx context.Context, repository *graveler.RepositoryRecord, branchID graveler.BranchID) (*graveler.Branch, error) {
	branch, err := m.RefManager.GetBranch(ctx, repository, branchID)
	if err != nil {
		return nil, err
	}
	compactedBranch := *branch
	compactedBranch.CompactedBaseMetaRangeID = m.compacted
	return &compactedBranch, nil
}

func TestDiffFilteredTwoDotIncludesStagedVersions(t *testing.T) {
	f := newDiffFilterFixture(t, "two_dot")
	f.put(t, "main", "changed", "U", "old")
	f.put(t, "main", "downgrade", "TS", "old")
	f.startChanges(t)
	f.put(t, f.right, "added", "U", "staged")
	f.put(t, f.right, "changed", "U", "staged")
	f.put(t, f.right, "downgrade", "U", "staged")
	// Two-dot explicitly includes uncommitted changes with the staging modifier.
	f.right += "$"
	recorder, result := f.diff(t, f.request(t, "U"), apigen.DiffRefsParams{IncludeRightStats: swag.Bool(true)})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, []string{"added", "changed"}, diffPaths(result))
	require.NotContains(t, recorder.Body.String(), "downgrade")
	for _, row := range result.Results {
		require.Equal(t, "staged", row.Right.Metadata.AdditionalProperties["revision"])
	}
	require.Equal(t, 1, f.authorizer.policyLoads)
}

func requireDiffHistoricalStats(t *testing.T, results []apigen.Diff, withStats bool) {
	t.Helper()
	for _, row := range results {
		if withStats {
			require.NotNil(t, row.Right)
			require.Equal(t, "U", row.Right.Metadata.AdditionalProperties["dcs:cls"])
			require.Equal(t, "text/plain", row.Right.ContentType)
			require.Equal(t, int64(1700000000), row.Right.Mtime)
			if row.Type == "removed" {
				require.Equal(t, "removed-u-old", row.Right.Checksum, "preserve legacy deletion statistics")
			}
		} else {
			require.Nil(t, row.Right)
		}
	}
}
