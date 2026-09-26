package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	authacl "github.com/treeverse/lakefs/contrib/auth/acl"
	"github.com/treeverse/lakefs/pkg/api"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	authparams "github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
	"github.com/treeverse/lakefs/pkg/stats"
)

type filteredListingAuth struct {
	auth.Service
	policyLoads    int
	reads          int
	afterFirstRead func()
	readError      error
}

func (s *filteredListingAuth) ListEffectivePolicies(ctx context.Context, username string, params *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	s.policyLoads++
	return s.Service.ListEffectivePolicies(ctx, username, params)
}

func (s *filteredListingAuth) Authorize(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	if _, err := auth.AuthorizationPolicies(ctx, req, s.ListEffectivePolicies); err != nil {
		return nil, err
	}
	if req.RequiredPermissions.Permission.Action == permissions.ReadObjectAction {
		s.reads++
		if s.readError != nil && s.reads > 1 {
			return nil, s.readError
		}
		if s.reads == 1 && s.afterFirstRead != nil {
			s.afterFirstRead()
		}
	}
	return s.Service.Authorize(ctx, req)
}

type filteredListingAdapter struct {
	block.Adapter
	signed []string
}

func (a *filteredListingAdapter) GetPreSignedURL(_ context.Context, _ block.ObjectPointer, _ block.PreSignMode, filename string) (string, time.Time, error) {
	a.signed = append(a.signed, filename)
	return "https://signed.example/" + filename, time.Unix(2_000_000_000, 0), nil
}

type filteredListingFixture struct {
	controller *api.Controller
	auth       *filteredListingAuth
	adapter    *filteredListingAdapter
	repository string
	user       *model.User
}

func newFilteredListingFixture(t *testing.T) *filteredListingFixture {
	t.Helper()
	_, deps := setupHandler(t)
	service := authacl.NewAuthService(kvtest.GetStore(t.Context(), t), crypt.NewSecretStore([]byte("listing-test")), authparams.ServiceCache{}, true)
	user := &model.User{Username: "listing-reader"}
	_, err := service.CreateUser(t.Context(), user)
	require.NoError(t, err)
	counted := &filteredListingAuth{Service: service}
	adapter := &filteredListingAdapter{Adapter: deps.blocks}
	f := &filteredListingFixture{
		controller: &api.Controller{Catalog: deps.catalog, Auth: counted, BlockAdapter: adapter, Logger: logging.Dummy(), Collector: &stats.NullCollector{}},
		auth:       counted, adapter: adapter, repository: testUniqueRepoName(), user: user,
	}
	_, err = deps.catalog.CreateRepository(t.Context(), f.repository, config.SingleBlockstoreID, onBlock(deps, "filtered-listing"), "main", false)
	require.NoError(t, err)
	f.setPolicy(t, listingStatements())
	require.NoError(t, service.AttachPolicyToUser(t.Context(), "listing-policy", user.Username))
	return f
}

func listingStatements() model.Statements {
	statements := model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction}, Resource: "*"}}
	classes := []string{"U", "R", "S", "TS"}
	for rank, clearance := range classes {
		statements = append(statements, model.Statement{
			Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*",
			Condition: map[string]map[string][]string{"StringEquals": {
				"aws:PrincipalTag/clr": {clearance}, "lakefs:ObjectMetadata/dcs:cls": classes[:rank+1],
			}},
		})
	}
	return statements
}

func (f *filteredListingFixture) setPolicy(t *testing.T, statements model.Statements) {
	t.Helper()
	_, err := f.auth.GetPolicy(t.Context(), "listing-policy")
	require.NoError(t, f.auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "listing-policy", Statement: statements}, err == nil))
}

func (f *filteredListingFixture) add(t *testing.T, path, classification string) {
	t.Helper()
	var metadata catalog.Metadata
	if classification != "" {
		metadata = catalog.Metadata{"dcs:cls": classification}
	}
	require.NoError(t, f.controller.Catalog.CreateEntry(t.Context(), f.repository, "main", catalog.DBEntry{
		Path: path, PhysicalAddress: path, AddressType: catalog.AddressTypeRelative, Metadata: metadata, CreationDate: time.Now(),
	}))
}

func (f *filteredListingFixture) list(t *testing.T, clearance string, params apigen.ListObjectsParams) (*httptest.ResponseRecorder, apigen.ObjectStatsList) {
	t.Helper()
	ctx := auth.WithPrincipalTags(auth.WithUser(t.Context(), f.user), principaltags.Tags{"clr": clearance})
	req := httptest.NewRequest(http.MethodGet, "http://lakefs.example/", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	f.controller.ListObjects(recorder, req, f.repository, "main", params)
	var result apigen.ObjectStatsList
	if recorder.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
	}
	return recorder, result
}

func listingPaths(result apigen.ObjectStatsList) []string {
	paths := make([]string, 0, len(result.Results))
	for _, entry := range result.Results {
		paths = append(paths, entry.Path)
	}
	return paths
}

func TestListObjectsFiltersReadPermissions(t *testing.T) {
	f := newFilteredListingFixture(t)
	for _, cls := range []string{"U", "R", "S", "TS", "unknown"} {
		f.add(t, cls+".txt", cls)
	}
	f.add(t, "missing.txt", "")
	for _, presign := range []bool{false, true} {
		for _, tc := range []struct {
			clearance string
			paths     []string
		}{
			{"U", []string{"U.txt"}}, {"R", []string{"R.txt", "U.txt"}},
			{"S", []string{"R.txt", "S.txt", "U.txt"}}, {"TS", []string{"R.txt", "S.txt", "TS.txt", "U.txt"}},
			{"", []string{}}, {"unknown", []string{}},
		} {
			t.Run(tc.clearance+"/presign="+strconv.FormatBool(presign), func(t *testing.T) {
				loads := f.auth.policyLoads
				f.adapter.signed = nil
				recorder, result := f.list(t, tc.clearance, apigen.ListObjectsParams{Presign: swag.Bool(presign), UserMetadata: swag.Bool(false)})
				require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				require.Equal(t, tc.paths, listingPaths(result))
				require.Equal(t, loads+1, f.auth.policyLoads, "one policy snapshot for gate and every object")
				require.False(t, result.Pagination.HasMore)
				require.Equal(t, len(tc.paths), result.Pagination.Results)
				for _, entry := range result.Results {
					require.Nil(t, entry.Metadata, "metadata is still used for authorization when omitted from response")
				}
				if presign {
					require.Equal(t, tc.paths, append([]string{}, f.adapter.signed...))
				} else {
					require.Empty(t, f.adapter.signed)
				}
			})
		}
	}
}

func TestListObjectsFilteredPaginationAndDirectories(t *testing.T) {
	f := newFilteredListingFixture(t)
	f.add(t, "a-hidden/file", "TS")
	f.add(t, "b-mixed/1-hidden", "TS")
	f.add(t, "b-mixed/2-visible", "U")
	f.add(t, "b-mixed/3-visible", "U")
	f.add(t, "c-hidden", "TS")
	f.add(t, "d-visible", "U")
	f.add(t, "z-hidden", "TS")
	for _, delimiter := range []string{"", "/"} {
		t.Run("delimiter="+delimiter, func(t *testing.T) {
			expected := []string{"b-mixed/2-visible", "b-mixed/3-visible", "d-visible"}
			if delimiter == "/" {
				expected = []string{"b-mixed/", "d-visible"}
			}
			amount := apigen.PaginationAmount(1)
			delimiterParam := apigen.PaginationDelimiter(delimiter)
			params := apigen.ListObjectsParams{Amount: &amount, Delimiter: &delimiterParam}
			for i, path := range expected {
				recorder, result := f.list(t, "U", params)
				require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				require.Equal(t, []string{path}, listingPaths(result))
				require.Equal(t, i+1 < len(expected), result.Pagination.HasMore)
				if result.Pagination.HasMore {
					require.Equal(t, path, result.Pagination.NextOffset)
					after := apigen.PaginationAfter(result.Pagination.NextOffset)
					params.After = &after
				} else {
					require.Empty(t, result.Pagination.NextOffset)
				}
			}
		})
	}
	prefix := apigen.PaginationPrefix("a-hidden/")
	recorder, result := f.list(t, "U", apigen.ListObjectsParams{Prefix: &prefix})
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Empty(t, result.Results)
	require.False(t, result.Pagination.HasMore)
}

func TestListObjectsKeepsSnapshotUntilNextRequest(t *testing.T) {
	f := newFilteredListingFixture(t)
	f.add(t, "a", "U")
	f.add(t, "b", "U")
	// A concurrent policy change after the list gate applies to the next API
	// request, even if the current request evaluates more objects afterwards.
	f.auth.afterFirstRead = func() {
		f.setPolicy(t, model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction}, Resource: "*"}})
	}
	recorder, result := f.list(t, "U", apigen.ListObjectsParams{Presign: swag.Bool(true)})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, []string{"a", "b"}, listingPaths(result))
	require.Equal(t, 1, f.auth.policyLoads)
	recorder, result = f.list(t, "U", apigen.ListObjectsParams{})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Empty(t, result.Results)
	require.Equal(t, 2, f.auth.policyLoads)
}

func TestListObjectsExplicitDenyAndNull(t *testing.T) {
	f := newFilteredListingFixture(t)
	f.add(t, "visible", "U")
	f.add(t, "denied", "S")
	f.add(t, "unclassified", "")
	f.setPolicy(t, model.Statements{
		{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction, permissions.ReadObjectAction}, Resource: "*"},
		{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: "*", Condition: map[string]map[string][]string{"StringEquals": {"lakefs:ObjectMetadata/dcs:cls": {"S"}}}},
		{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: "*", Condition: map[string]map[string][]string{"Null": {"lakefs:ObjectMetadata/dcs:cls": {"true"}}}},
	})
	recorder, result := f.list(t, "TS", apigen.ListObjectsParams{})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, []string{"visible"}, listingPaths(result))
}

func TestListObjectsFilterErrorReturnsNoPartialResults(t *testing.T) {
	f := newFilteredListingFixture(t)
	f.add(t, "a", "U")
	f.add(t, "b", "U")
	f.auth.readError = errors.New("test authorizer unavailable")
	recorder, _ := f.list(t, "U", apigen.ListObjectsParams{Presign: swag.Bool(true)})
	require.Equal(t, http.StatusInternalServerError, recorder.Code, recorder.Body.String())
	require.NotContains(t, recorder.Body.String(), "physical_address")
	require.Empty(t, f.adapter.signed)
}

func TestListObjectsRequiresListPermission(t *testing.T) {
	f := newFilteredListingFixture(t)
	f.setPolicy(t, model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*"}})
	recorder, _ := f.list(t, "U", apigen.ListObjectsParams{})
	require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
	require.Zero(t, f.auth.reads)
}
