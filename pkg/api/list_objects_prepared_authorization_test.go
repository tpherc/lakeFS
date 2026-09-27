package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"

	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	authparams "github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
)

// Observe the same snapshot-aware lookup path as production authorization so
// unprepared per-object checks cannot bypass the policy-load counter.
type listPresignAuth struct {
	auth.Service
	policyLoads    int
	authorizeCalls int
	failOnLoad     int
	prepareErr     error
}

func (s *listPresignAuth) ListEffectivePolicies(ctx context.Context, username string, params *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	s.policyLoads++
	if s.prepareErr != nil && s.policyLoads == s.failOnLoad {
		return nil, nil, s.prepareErr
	}
	return s.Service.ListEffectivePolicies(ctx, username, params)
}

func (s *listPresignAuth) Authorize(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	s.authorizeCalls++
	if _, err := auth.AuthorizationPolicies(ctx, req, s.ListEffectivePolicies); err != nil && !errors.Is(err, auth.ErrNotImplemented) {
		return nil, err
	}
	return s.Service.Authorize(ctx, req)
}

type listPresignStore struct {
	catalog.Store
	repositoryLookups int
}

func (s *listPresignStore) GetRepository(ctx context.Context, repositoryID graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	s.repositoryLookups++
	return s.Store.GetRepository(ctx, repositoryID)
}

type listPresignAdapter struct {
	block.Adapter
	namespaceResolutions int
	signingCalls         int
}

func (a *listPresignAdapter) ResolveNamespace(storageID, storageNamespace, key string, identifierType block.IdentifierType) (block.QualifiedKey, error) {
	a.namespaceResolutions++
	return a.Adapter.ResolveNamespace(storageID, storageNamespace, key, identifierType)
}

func (a *listPresignAdapter) GetPreSignedURL(ctx context.Context, object block.ObjectPointer, mode block.PreSignMode, filename string) (string, time.Time, error) {
	a.signingCalls++
	return a.Adapter.GetPreSignedURL(ctx, object, mode, filename)
}

func TestListObjectsPreparedAuthorizationTagsAndMetadata(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{
		DisplayName: "object-classification",
		Statement: model.Statements{
			{Effect: model.StatementEffectAllow, Action: []string{permissions.ListObjectsAction}, Resource: permissions.RepoArn(f.repository)},
			{
				Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction},
				Resource: permissions.ObjectArn(f.repository, "${aws:PrincipalTag/team}/*"),
				Condition: map[string]map[string][]string{
					"StringEquals": {"lakefs:ObjectMetadata/team": {"${aws:PrincipalTag/team}"}},
				},
			},
		},
	}, true))
	f.createObject(t, "blue/allowed.txt", catalog.Metadata{"team": "blue"})
	f.createObject(t, "blue/wrong-metadata.txt", catalog.Metadata{"team": "red"})
	f.createObject(t, "blue/missing-metadata.txt", nil)
	f.createObject(t, "red/wrong-path.txt", catalog.Metadata{"team": "blue"})
	service := f.controller.Auth
	for _, presign := range []bool{false, true} {
		name := "ordinary listing"
		if presign {
			name = "presigned listing"
		}
		t.Run(name, func(t *testing.T) {
			counting := &listPresignAuth{Service: service}
			f.controller.Auth = counting
			req := f.request(t, http.MethodGet, "")
			req = req.WithContext(auth.WithPrincipalTags(req.Context(), principaltags.Tags{"team": "blue"}))
			recorder := httptest.NewRecorder()
			f.controller.ListObjects(recorder, req, f.repository, "main", apigen.ListObjectsParams{
				Presign: swag.Bool(presign), UserMetadata: swag.Bool(false),
			})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, 1, counting.policyLoads, "initial and per-object authorization share one operation snapshot")
			require.Equal(t, 5, counting.authorizeCalls, "ordinary and presigned listings check list permission and every object's read permission")
			var result apigen.ObjectStatsList
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
			require.Len(t, result.Results, 1)
			require.Equal(t, "blue/allowed.txt", result.Results[0].Path)
			for _, object := range result.Results {
				require.Nil(t, object.Metadata, object.Path)
				if presign {
					require.Equal(t, metadataSignedURLPrefix+url.PathEscape(object.Path), object.PhysicalAddress)
					require.NotNil(t, object.PhysicalAddressExpiry)
				} else {
					require.NotContains(t, object.PhysicalAddress, metadataSignedURLPrefix, object.Path)
					require.Nil(t, object.PhysicalAddressExpiry, object.Path)
				}
			}
		})
	}
}

func TestListObjectsPreparedAuthorizationBasicAuthFallback(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	f.createObject(t, "first.txt", nil)
	f.createObject(t, "second.txt", catalog.Metadata{"team": "restricted"})
	service := auth.NewBasicAuthService(kvtest.GetStore(t.Context(), t), crypt.NewSecretStore([]byte("list-basic-auth-secret")), authparams.ServiceCache{}, logging.Dummy())
	_, err := service.CreateUser(t.Context(), &model.User{Username: f.user.Username})
	require.NoError(t, err)
	counting := &listPresignAuth{Service: service}
	f.controller.Auth = counting
	recorder := httptest.NewRecorder()
	f.controller.ListObjects(recorder, f.request(t, http.MethodGet, ""), f.repository, "main", apigen.ListObjectsParams{Presign: swag.Bool(true)})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, 4, counting.policyLoads, "unsupported snapshot loading preserves initial and per-object BasicAuth checks")
	require.Equal(t, 3, counting.authorizeCalls, "BasicAuth still checks the list and both objects")
	var result apigen.ObjectStatsList
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
	require.Len(t, result.Results, 2)
	for _, object := range result.Results {
		require.Equal(t, metadataSignedURLPrefix+object.Path, object.PhysicalAddress)
		require.NotNil(t, object.PhysicalAddressExpiry)
	}
}

func TestListObjectsPreparedAuthorizationEmptyListing(t *testing.T) {
	for _, presign := range []bool{false, true} {
		name := "ordinary listing"
		if presign {
			name = "presigned listing"
		}
		t.Run(name, func(t *testing.T) {
			f := newMetadataAuthorizationFixture(t)
			counting := &listPresignAuth{Service: f.controller.Auth}
			f.controller.Auth = counting
			adapter := &listPresignAdapter{Adapter: f.controller.BlockAdapter}
			f.controller.BlockAdapter = adapter
			recorder := httptest.NewRecorder()
			f.controller.ListObjects(recorder, f.request(t, http.MethodGet, "R"), f.repository, "main", apigen.ListObjectsParams{Presign: swag.Bool(presign)})
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, 1, counting.policyLoads)
			require.Equal(t, 1, counting.authorizeCalls, "empty lists must still be authorized")
			var result apigen.ObjectStatsList
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
			require.Empty(t, result.Results)
			require.Zero(t, adapter.namespaceResolutions)
			require.Zero(t, adapter.signingCalls)
		})
	}
}

func TestListObjectsPreparedAuthorizationDeniedBeforeStorage(t *testing.T) {
	for _, presign := range []bool{false, true} {
		name := "ordinary listing"
		if presign {
			name = "presigned listing"
		}
		t.Run(name, func(t *testing.T) {
			f := newMetadataAuthorizationFixture(t)
			f.createObject(t, "first.txt", catalog.Metadata{"dcs:cls": "U"})
			require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{
				DisplayName: "object-classification",
				Statement: model.Statements{{
					Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*",
				}},
			}, true))
			counting := &listPresignAuth{Service: f.controller.Auth}
			f.controller.Auth = counting
			store := &listPresignStore{Store: f.controller.Catalog.Store}
			f.controller.Catalog.Store = store
			adapter := &listPresignAdapter{Adapter: f.controller.BlockAdapter}
			f.controller.BlockAdapter = adapter
			recorder := httptest.NewRecorder()
			f.controller.ListObjects(recorder, f.request(t, http.MethodGet, "R"), f.repository, "main", apigen.ListObjectsParams{Presign: swag.Bool(presign)})
			require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
			require.Equal(t, 1, counting.policyLoads)
			require.Equal(t, 1, counting.authorizeCalls)
			require.Zero(t, store.repositoryLookups, "list denial must precede catalog access")
			require.Zero(t, adapter.namespaceResolutions)
			require.Zero(t, adapter.signingCalls)
			require.NotContains(t, recorder.Body.String(), metadataSignedURLPrefix)
		})
	}
}

func TestListObjectsPreparedAuthorizationLoadFailure(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	f.createObject(t, "first.txt", catalog.Metadata{"dcs:cls": "U"})
	counting := &listPresignAuth{Service: f.controller.Auth, failOnLoad: 1, prepareErr: errors.New("policy snapshot unavailable")}
	f.controller.Auth = counting
	store := &listPresignStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	adapter := &listPresignAdapter{Adapter: f.controller.BlockAdapter}
	f.controller.BlockAdapter = adapter
	recorder := httptest.NewRecorder()
	f.controller.ListObjects(recorder, f.request(t, http.MethodGet, "R"), f.repository, "main", apigen.ListObjectsParams{Presign: swag.Bool(true)})
	require.Equal(t, http.StatusInternalServerError, recorder.Code, recorder.Body.String())
	require.Equal(t, 1, counting.policyLoads)
	require.Zero(t, counting.authorizeCalls, "preparation must precede initial list authorization")
	require.Zero(t, store.repositoryLookups, "preparation failure must precede catalog access")
	require.Zero(t, adapter.namespaceResolutions)
	require.Zero(t, adapter.signingCalls)
	require.NotContains(t, recorder.Body.String(), metadataSignedURLPrefix)
}

func TestListObjectsPreparedAuthorizationRequiresUser(t *testing.T) {
	for _, presign := range []bool{false, true} {
		name := "ordinary listing"
		if presign {
			name = "presigned listing"
		}
		t.Run(name, func(t *testing.T) {
			f := newMetadataAuthorizationFixture(t)
			counting := &listPresignAuth{Service: f.controller.Auth}
			f.controller.Auth = counting
			store := &listPresignStore{Store: f.controller.Catalog.Store}
			f.controller.Catalog.Store = store
			adapter := &listPresignAdapter{Adapter: f.controller.BlockAdapter}
			f.controller.BlockAdapter = adapter
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "http://lakefs.example/", nil)
			f.controller.ListObjects(recorder, request, f.repository, "main", apigen.ListObjectsParams{Presign: swag.Bool(presign)})
			require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
			require.Zero(t, counting.policyLoads)
			require.Zero(t, counting.authorizeCalls)
			require.Zero(t, store.repositoryLookups)
			require.Zero(t, adapter.namespaceResolutions)
			require.Zero(t, adapter.signingCalls)
		})
	}
}

func TestListPresignAuthCountsUnpreparedChecks(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	counting := &listPresignAuth{Service: f.controller.Auth}
	ctx := f.request(t, http.MethodGet, "R").Context()
	request := &auth.AuthorizationRequest{
		Username: f.user.Username,
		RequiredPermissions: permissions.Node{Permission: permissions.Permission{
			Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn(f.repository, "object"),
			ObjectMetadata: map[string]string{"dcs:cls": "U"},
		}},
	}
	for range 2 {
		response, err := counting.Authorize(ctx, request)
		require.NoError(t, err)
		require.True(t, response.Allowed)
	}
	require.Equal(t, 2, counting.policyLoads, "each unprepared object check must be observable")

	prepared, err := auth.PrepareAuthorization(ctx, counting, f.user.Username)
	require.NoError(t, err)
	for range 2 {
		response, err := prepared.Authorize(ctx, request)
		require.NoError(t, err)
		require.True(t, response.Allowed)
	}
	require.Equal(t, 3, counting.policyLoads, "prepared checks use their shared snapshot")
}
