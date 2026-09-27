package gateway

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/catalog"
	catalogtest "github.com/treeverse/lakefs/pkg/catalog/testutils"
	"github.com/treeverse/lakefs/pkg/gateway/operations"
	"github.com/treeverse/lakefs/pkg/graveler"
	gravelertest "github.com/treeverse/lakefs/pkg/graveler/testutil"
	"github.com/treeverse/lakefs/pkg/permissions"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const listingRepository = "list-auth"

type listingPolicyService struct {
	auth.GatewayService
	policies    []*model.Policy
	policyLoads int
	readChecks  int
	failRead    int
	basicAuth   bool
}

func (s *listingPolicyService) ListEffectivePolicies(context.Context, string, *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	s.policyLoads++
	if s.basicAuth {
		return nil, nil, auth.ErrNotImplemented
	}
	return s.policies, nil, nil
}

func (s *listingPolicyService) Authorize(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	if req.RequiredPermissions.Permission.Action == permissions.ReadObjectAction {
		s.readChecks++
		if s.failRead == s.readChecks {
			return nil, context.DeadlineExceeded
		}
	}
	if s.basicAuth {
		return &auth.AuthorizationResponse{Allowed: true}, nil
	}
	policies, err := auth.AuthorizationPolicies(ctx, req, s.ListEffectivePolicies)
	if err != nil {
		return nil, err
	}
	allowed := auth.CheckRequestPermissions(ctx, req, policies, &auth.MissingPermissions{}) == auth.CheckAllow
	response := &auth.AuthorizationResponse{Allowed: allowed}
	if !allowed {
		response.Error = auth.ErrInsufficientPermissions
	}
	return response, nil
}

type listingStore struct {
	catalog.Store
	records    []*graveler.ValueRecord
	beforeList func()
	listCalls  int
}

func (s *listingStore) GetRepository(_ context.Context, id graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	return &graveler.RepositoryRecord{RepositoryID: id}, nil
}

func (s *listingStore) List(context.Context, *graveler.RepositoryRecord, graveler.Ref, int) (graveler.ValueIterator, error) {
	s.listCalls++
	if s.beforeList != nil {
		s.beforeList()
	}
	return catalogtest.NewFakeValueIterator(s.records), nil
}

func (s *listingStore) ListBranches(context.Context, *graveler.RepositoryRecord, ...graveler.ListOptionsFunc) (graveler.BranchIterator, error) {
	return gravelertest.NewFakeBranchIterator([]*graveler.BranchRecord{{BranchID: "main", Branch: &graveler.Branch{CommitID: "commit"}}}), nil
}

func listingPolicies() []*model.Policy {
	return []*model.Policy{{Statement: model.Statements{
		{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction, permissions.ListBranchesAction}, Resource: permissions.RepoArn(listingRepository)},
		{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn(listingRepository, "*"), Condition: map[string]map[string][]string{
			"StringEquals": {"lakefs:ObjectMetadata/dcs:cls": {"U"}, "aws:PrincipalTag/clr": {"U"}},
		}},
		{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn(listingRepository, "g-denied")},
	}}}
}

func newListingStore() *listingStore {
	store := &listingStore{}
	for _, object := range []struct{ path, classification string }{
		{"a-hidden", "S"},
		{"b-visible", "U"},
		{"c-hidden", "TS"},
		{"d-prefix/hidden", "S"},
		{"d-prefix/public", "U"},
		{"e-hidden-prefix/secret", "TS"},
		{"f-visible", "U"},
		{"g-denied", "U"},
		{"h-unclassified", ""},
	} {
		entry := &catalog.Entry{Address: object.path, LastModified: timestamppb.New(time.Unix(1, 0)), ETag: "checksum", Size: 1}
		if object.classification != "" {
			entry.Metadata = map[string]string{"dcs:cls": object.classification}
		}
		store.records = append(store.records, &graveler.ValueRecord{Key: graveler.Key(object.path), Value: catalog.MustEntryToValue(entry)})
	}
	return store
}

func serveList(t *testing.T, service *listingPolicyService, store *listingStore, version string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	query.Set("list-type", version)
	req := httptest.NewRequest(http.MethodGet, "/"+listingRepository+"?"+query.Encode(), nil)
	c := &catalog.Catalog{Store: store}
	ctx := auth.WithPrincipalTags(auth.WithUser(req.Context(), &model.User{Username: "alice"}), principaltags.Tags{"clr": "U"})
	ctx = context.WithValue(ctx, ContextKeyRepository, &catalog.Repository{Name: listingRepository})
	ctx = context.WithValue(ctx, ContextKeyMatchedHost, false)
	ctx = context.WithValue(ctx, ContextKeyOperation, &operations.Operation{
		OperationID: operations.OperationIDListObjects,
		Catalog:     c,
		Auth:        service,
		Incr:        func(string, string, string, string) {},
	})
	recorder := httptest.NewRecorder()
	RepoOperationHandler(&ServerContext{catalog: c, authService: service}, &operations.ListObjects{}).ServeHTTP(recorder, req.WithContext(ctx))
	return recorder
}

type listingXML struct {
	Keys       []string `xml:"Contents>Key"`
	Prefixes   []string `xml:"CommonPrefixes>Prefix"`
	KeyCount   int      `xml:"KeyCount"`
	Truncated  bool     `xml:"IsTruncated"`
	NextMarker string   `xml:"NextMarker"`
	NextToken  string   `xml:"NextContinuationToken"`
}

func decodeList(t *testing.T, recorder *httptest.ResponseRecorder) listingXML {
	t.Helper()
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var response listingXML
	require.NoError(t, xml.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}

func TestListObjectsReadFilteringPagination(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			service := &listingPolicyService{policies: listingPolicies()}
			store := newListingStore()
			query := url.Values{"prefix": {"main/"}, "delimiter": {"/"}, "max-keys": {"2"}}
			first := decodeList(t, serveList(t, service, store, version, query))
			require.Equal(t, []string{"main/b-visible"}, first.Keys)
			require.Equal(t, []string{"main/d-prefix/"}, first.Prefixes)
			require.Equal(t, 2, first.KeyCount)
			require.True(t, first.Truncated)
			marker := first.NextMarker
			markerParam := "marker"
			if version == "2" {
				marker, markerParam = first.NextToken, "continuation-token"
			}
			require.Equal(t, "main/d-prefix/", marker)
			require.Equal(t, 1, service.policyLoads)
			query.Set(markerParam, marker)
			second := decodeList(t, serveList(t, service, store, version, query))
			require.Equal(t, []string{"main/f-visible"}, second.Keys)
			require.Empty(t, second.Prefixes)
			require.Equal(t, 1, second.KeyCount)
			require.False(t, second.Truncated)
			require.Empty(t, second.NextToken)
			require.Empty(t, second.NextMarker)
			require.Equal(t, 2, service.policyLoads)
			require.Equal(t, 2, store.listCalls)
		})
	}
}

func TestListObjectsReadFilteringEmptyAndRecursive(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		for _, tc := range []struct {
			name, prefix string
			keys         []string
		}{
			{name: "all denied", prefix: "main/e-hidden-prefix/"},
			{name: "recursive", prefix: "main/", keys: []string{"main/b-visible", "main/d-prefix/public", "main/f-visible"}},
		} {
			t.Run("v"+version+"/"+tc.name, func(t *testing.T) {
				service := &listingPolicyService{policies: listingPolicies()}
				response := decodeList(t, serveList(t, service, newListingStore(), version, url.Values{"prefix": {tc.prefix}}))
				require.Equal(t, tc.keys, response.Keys)
				require.Equal(t, len(tc.keys), response.KeyCount)
				require.Empty(t, response.Prefixes)
				require.Empty(t, response.NextMarker)
				require.Empty(t, response.NextToken)
				require.False(t, response.Truncated)
				require.Equal(t, 1, service.policyLoads)
			})
		}
	}
}

func TestListObjectsReadFilteringPolicySnapshot(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			service := &listingPolicyService{policies: listingPolicies()}
			store := newListingStore()
			store.beforeList = func() {
				service.policies = []*model.Policy{{Statement: model.Statements{listingPolicies()[0].Statement[0]}}}
			}
			query := url.Values{"prefix": {"main/"}}
			first := decodeList(t, serveList(t, service, store, version, query))
			require.Len(t, first.Keys, 3, "policy changes after initial authorization must not change this response")
			require.Equal(t, 1, service.policyLoads)
			second := decodeList(t, serveList(t, service, store, version, query))
			require.Empty(t, second.Keys, "the next API call must use the current policy snapshot")
			require.False(t, second.Truncated)
			require.Equal(t, 2, service.policyLoads)
		})
	}
}

func TestListObjectsReadFilteringRequiresListPermission(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			policies := listingPolicies()
			policies[0].Statement = policies[0].Statement[1:]
			service := &listingPolicyService{policies: policies}
			store := newListingStore()
			response := serveList(t, service, store, version, url.Values{"prefix": {"main/"}})
			require.Equal(t, http.StatusForbidden, response.Code)
			require.Zero(t, store.listCalls)
			require.Zero(t, service.readChecks)
		})
	}
}

func TestListObjectsReadFilteringErrorDiscardsPartialPage(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			service := &listingPolicyService{policies: listingPolicies(), failRead: 3}
			response := serveList(t, service, newListingStore(), version, url.Values{"prefix": {"main/"}})
			require.NotEqual(t, http.StatusOK, response.Code)
			require.NotContains(t, response.Body.String(), "main/b-visible")
			require.NotContains(t, response.Body.String(), "<Contents>")
		})
	}
}

func TestListObjectsReadFilteringBasicAuth(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			service := &listingPolicyService{basicAuth: true}
			store := newListingStore()
			response := decodeList(t, serveList(t, service, store, version, url.Values{"prefix": {"main/"}}))
			require.Len(t, response.Keys, len(store.records))
			require.Equal(t, len(store.records), service.readChecks)
			require.Equal(t, 1, service.policyLoads)
		})
	}
}

func TestListObjectsBranchListingDoesNotRequireObjectRead(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			policies := listingPolicies()
			policies[0].Statement = policies[0].Statement[:1]
			service := &listingPolicyService{policies: policies}
			store := newListingStore()
			response := decodeList(t, serveList(t, service, store, version, url.Values{"delimiter": {"/"}, "max-keys": {"10"}}))
			require.Equal(t, []string{"main/"}, response.Prefixes)
			require.Zero(t, service.readChecks)
			require.Zero(t, store.listCalls)
		})
	}
}
