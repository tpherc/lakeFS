package api_test

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	authacl "github.com/treeverse/lakefs/contrib/auth/acl"
	"github.com/treeverse/lakefs/pkg/api"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	authmock "github.com/treeverse/lakefs/pkg/auth/mock"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	authparams "github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/gateway/operations"
	"github.com/treeverse/lakefs/pkg/gateway/serde"
	"github.com/treeverse/lakefs/pkg/graveler"
	gravelermock "github.com/treeverse/lakefs/pkg/graveler/mock"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
	"github.com/treeverse/lakefs/pkg/stats"
)

// These tests start with an authenticated principal snapshot and exercise each
// enforcement entry point, including real catalog filtering for REST and S3.
func TestPrincipalTagsAuthorizationPaths(t *testing.T) {
	t.Parallel()
	condition := func(operator, field, value string) map[string]map[string][]string {
		return map[string]map[string][]string{operator: {field: {value}}}
	}
	tagCondition := condition("StringLike", "AWS:PrincipalTag/CLR", "S")
	for _, tc := range []struct {
		name        string
		tags        principaltags.Tags
		effect      string
		condition   map[string]map[string][]string
		broadAllow  bool
		allowed     bool
		filterError bool
	}{
		{name: "tag conditioned allow", tags: principaltags.Tags{"clr": "S"}, effect: model.StatementEffectAllow, condition: tagCondition, allowed: true},
		{name: "tag conditioned deny", tags: principaltags.Tags{"clr": "S"}, effect: model.StatementEffectDeny, condition: tagCondition},
		{name: "broad allow and tag deny", tags: principaltags.Tags{"clr": "S"}, effect: model.StatementEffectDeny, condition: tagCondition, broadAllow: true},
		{name: "missing tag allow", effect: model.StatementEffectAllow, condition: tagCondition},
		{name: "missing tag deny with broad allow", effect: model.StatementEffectDeny, condition: tagCondition, broadAllow: true, allowed: true},
		{name: "value case sensitive", tags: principaltags.Tags{"clr": "s"}, effect: model.StatementEffectAllow, condition: tagCondition},
		{name: "unsupported condition fails closed", tags: principaltags.Tags{"clr": "S"}, effect: model.StatementEffectDeny, condition: condition("Unsupported", "aws:PrincipalTag/clr", "S"), broadAllow: true, filterError: true},
		{name: "invalid tag IP fails closed", tags: principaltags.Tags{"clr": "S"}, effect: model.StatementEffectDeny, condition: condition("IpAddress", "aws:PrincipalTag/clr", "192.0.2.0/24"), broadAllow: true, filterError: true},
		{name: "source IP allow", effect: model.StatementEffectAllow, condition: condition("IpAddress", "SourceIp", "192.0.2.0/24"), allowed: true},
		{name: "source IP mismatch", effect: model.StatementEffectAllow, condition: condition("IpAddress", "SourceIp", "198.51.100.0/24")},
		{name: "source IP deny", effect: model.StatementEffectDeny, condition: condition("IpAddress", "SourceIp", "192.0.2.0/24"), broadAllow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statements := model.Statements{{Effect: tc.effect, Action: []string{permissions.ListRepositoriesAction}, Resource: "*", Condition: tc.condition}}
			if tc.broadAllow {
				statements = append(model.Statements{{Effect: model.StatementEffectAllow, Action: []string{"fs:*"}, Resource: "*"}}, statements...)
			}
			policies := []*model.Policy{{DisplayName: "principal-tags-test", Statement: statements}}
			ctx := auth.WithPrincipalTags(auth.WithUser(t.Context(), &model.User{Username: "user"}), tc.tags)
			request := &auth.AuthorizationRequest{Username: "user", ClientIP: "192.0.2.42", RequiredPermissions: permissions.Node{
				Type:       permissions.NodeTypeNode,
				Permission: permissions.Permission{Action: permissions.ListRepositoriesAction, Resource: permissions.RepoArn("example")},
			}}

			t.Run("API auth", func(t *testing.T) {
				mockClient := authmock.NewMockClientWithResponsesInterface(gomock.NewController(t))
				// Serialize through the actual API shape, preserving conditions.
				encoded, err := json.Marshal(statements)
				require.NoError(t, err)
				var apiStatements []auth.Statement
				require.NoError(t, json.Unmarshal(encoded, &apiStatements))
				mockClient.EXPECT().ListUserPoliciesWithResponse(gomock.Any(), "user", gomock.Any()).Return(&auth.ListUserPoliciesResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					JSON200:      &auth.PolicyList{Results: []auth.Policy{{Name: "tags", Statement: apiStatements}}},
				}, nil)
				service, err := auth.NewAPIAuthServiceWithClient(mockClient, true, true, crypt.NewSecretStore([]byte("test-secret")), authparams.ServiceCache{}, logging.Dummy())
				require.NoError(t, err)
				response, err := service.Authorize(ctx, request)
				require.NoError(t, err)
				require.Equal(t, tc.allowed, response.Allowed)
				if !tc.allowed {
					require.ErrorIs(t, response.Error, auth.ErrInsufficientPermissions)
				}
			})

			t.Run("local ACL", func(t *testing.T) {
				store := kvtest.GetStore(ctx, t)
				service := authacl.NewAuthService(store, crypt.NewSecretStore([]byte("test-secret")), authparams.ServiceCache{}, true)
				_, err := service.CreateUser(ctx, &model.User{Username: "user"})
				require.NoError(t, err)
				err = service.WritePolicy(ctx, policies[0], false)
				if _, unsupported := tc.condition["Unsupported"]; unsupported {
					require.ErrorIs(t, err, model.ErrValidationError)
					// Imported/previously stored policies still need runtime validation.
					require.NoError(t, kv.SetMsg(ctx, store, model.PartitionKey, model.PolicyPath(policies[0].DisplayName), model.ProtoFromPolicy(policies[0])))
				} else {
					require.NoError(t, err)
				}
				require.NoError(t, service.AttachPolicyToUser(ctx, policies[0].DisplayName, "user"))
				response, err := service.Authorize(ctx, request)
				require.NoError(t, err)
				require.Equal(t, tc.allowed, response.Allowed)
				if !tc.allowed {
					require.ErrorIs(t, response.Error, auth.ErrInsufficientPermissions)
				}
			})

			for _, path := range []string{"REST", "S3"} {
				t.Run(path, func(t *testing.T) {
					hasAllow := tc.effect == model.StatementEffectAllow || tc.broadAllow
					catalog := repositoryListingCatalog(t, hasAllow, tc.filterError)
					service := &repositoryListingAuth{policies: policies}
					recorder := httptest.NewRecorder()
					req := httptest.NewRequest(http.MethodGet, "http://lakefs.example/", nil).WithContext(ctx)
					req.RemoteAddr = "192.0.2.42:54321"
					if path == "REST" {
						controller := &api.Controller{Catalog: catalog, Auth: service, Logger: logging.Dummy(), Collector: &stats.NullCollector{}}
						controller.ListRepositories(recorder, req, apigen.ListRepositoriesParams{})
					} else {
						operation := &operations.AuthorizedOperation{Operation: &operations.Operation{Catalog: catalog, Auth: service, Incr: func(string, string, string, string) {}}, Principal: "user"}
						(&operations.ListBuckets{}).Handle(recorder, req, operation)
					}
					if tc.filterError {
						require.Equal(t, http.StatusInternalServerError, recorder.Code)
						return
					}
					if !hasAllow {
						require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, recorder.Code)
						return
					}
					require.Equal(t, http.StatusOK, recorder.Code)
					var names []string
					if path == "REST" {
						var result apigen.RepositoryList
						require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
						for _, repo := range result.Results {
							names = append(names, repo.Id)
						}
					} else {
						var result serde.ListAllMyBucketsResult
						require.NoError(t, xml.Unmarshal(recorder.Body.Bytes(), &result))
						for _, bucket := range result.Buckets.Bucket {
							names = append(names, bucket.Name)
						}
					}
					if tc.allowed {
						require.Equal(t, []string{"example"}, names)
					} else {
						require.Empty(t, names)
					}
				})
			}
		})
	}
}

type repositoryListingAuth struct {
	auth.Service
	policies []*model.Policy
}

func (s *repositoryListingAuth) ListEffectivePolicies(context.Context, string, *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	return s.policies, nil, nil
}

type repositoryListingStore struct {
	catalog.Store
	iterator graveler.RepositoryIterator
}

func (s *repositoryListingStore) ListRepositories(context.Context) (graveler.RepositoryIterator, error) {
	return s.iterator, nil
}

func repositoryListingCatalog(t *testing.T, called, filterError bool) *catalog.Catalog {
	t.Helper()
	iterator := gravelermock.NewMockRepositoryIterator(gomock.NewController(t))
	if called {
		iterator.EXPECT().Next().Return(true)
		iterator.EXPECT().Value().Return(&graveler.RepositoryRecord{RepositoryID: "example", Repository: &graveler.Repository{DefaultBranchID: "main"}})
		iterator.EXPECT().Close()
		if !filterError {
			iterator.EXPECT().Next().Return(false)
			iterator.EXPECT().Err().Return(nil)
		}
	}
	return &catalog.Catalog{Store: &repositoryListingStore{iterator: iterator}}
}

func TestRepositoryListingMalformedPolicyFailsClosed(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"REST", "S3"} {
		t.Run(path, func(t *testing.T) {
			policies := []*model.Policy{{Statement: model.Statements{
				{Effect: model.StatementEffectAllow, Action: []string{"fs:*"}, Resource: "*"},
				{Effect: model.StatementEffectDeny, Action: []string{"fs:*"}, Resource: `["invalid",]`},
			}}}
			ctx := auth.WithUser(t.Context(), &model.User{Username: "user"})
			catalog := repositoryListingCatalog(t, true, true)
			service := &repositoryListingAuth{policies: policies}
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://lakefs.example/", nil).WithContext(ctx)
			if path == "REST" {
				controller := &api.Controller{Catalog: catalog, Auth: service, Logger: logging.Dummy(), Collector: &stats.NullCollector{}}
				controller.ListRepositories(recorder, req, apigen.ListRepositoriesParams{})
			} else {
				operation := &operations.AuthorizedOperation{Operation: &operations.Operation{Catalog: catalog, Auth: service, Incr: func(string, string, string, string) {}}, Principal: "user"}
				(&operations.ListBuckets{}).Handle(recorder, req, operation)
			}
			require.Equal(t, http.StatusInternalServerError, recorder.Code)
			require.NotContains(t, recorder.Body.String(), "example")
		})
	}
}
