package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/permissions"
)

type metadataLookupStore struct {
	catalog.Store
	lookups int
}

func (s *metadataLookupStore) Get(ctx context.Context, repo *graveler.RepositoryRecord, ref graveler.Ref, key graveler.Key, opts ...graveler.GetOptionsFunc) (*graveler.Value, error) {
	s.lookups++
	return s.Store.Get(ctx, repo, ref, key, opts...)
}

type metadataPolicyFailure struct{ auth.Service }

func (s *metadataPolicyFailure) ListEffectivePolicies(context.Context, string, *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	return nil, nil, errors.New("policy lookup failed")
}

func TestObjectMetadataShortCircuitReadPaths(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	// Alice may write here but no Allow covers reading this source path.
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "object-classification", Statement: model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.WriteObjectAction}, Resource: "*"}}}, true))
	for _, tc := range []struct {
		name, method string
		handle       func(http.ResponseWriter, *http.Request)
	}{
		{"get", http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
			f.controller.GetObject(w, r, f.repository, "main", apigen.GetObjectParams{Path: "source"})
		}},
		{"head", http.MethodHead, func(w http.ResponseWriter, r *http.Request) {
			f.controller.HeadObject(w, r, f.repository, "main", apigen.HeadObjectParams{Path: "source"})
		}},
		{"stat", http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
			f.controller.StatObject(w, r, f.repository, "main", apigen.StatObjectParams{Path: "source"})
		}},
		{"underlying properties", http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
			f.controller.GetUnderlyingProperties(w, r, f.repository, "main", apigen.GetUnderlyingPropertiesParams{Path: "source"})
		}},
		{"copy source", http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
			f.controller.CopyObject(w, r, apigen.CopyObjectJSONRequestBody{SrcPath: "source"}, f.repository, "main", apigen.CopyObjectParams{DestPath: "copy"})
		}},
		{"multipart source", http.MethodPut, func(w http.ResponseWriter, r *http.Request) {
			f.controller.UploadPartCopy(w, r, apigen.UploadPartCopyJSONRequestBody{CopySource: apigen.CopyPartSource{Repository: f.repository, Ref: "main", Path: "source"}}, f.repository, "main", "upload", 1, apigen.UploadPartCopyParams{Path: "copy"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tc.handle(recorder, f.request(t, tc.method, "S"))
			require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
			require.Zero(t, store.lookups, "path denial must precede object lookup")
			require.Empty(t, recorder.Header().Get("Location"))
			if tc.method == http.MethodHead {
				require.Empty(t, recorder.Body.String())
			}
		})
	}
}

func TestObjectMetadataShortCircuitCopyDestination(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "object-classification", Statement: model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*"}}}, true))
	recorder := httptest.NewRecorder()
	f.controller.CopyObject(recorder, f.request(t, http.MethodPost, "S"), apigen.CopyObjectJSONRequestBody{SrcPath: "source"}, f.repository, "main", apigen.CopyObjectParams{DestPath: "copy"})
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.Zero(t, store.lookups, "missing destination write permission must reject before loading source")
}

func TestObjectMetadataShortCircuitStillEvaluatesMetadata(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	f.createObject(t, "source", catalog.Metadata{"dcs:cls": "S"})
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	for _, tc := range []struct {
		name, clearance string
		status          int
	}{
		{"conditioned allow", "S", http.StatusOK},
		{"conditioned non-match", "U", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := store.lookups
			recorder := httptest.NewRecorder()
			f.controller.StatObject(recorder, f.request(t, http.MethodGet, tc.clearance), f.repository, "main", apigen.StatObjectParams{Path: "source"})
			require.Equal(t, tc.status, recorder.Code, recorder.Body.String())
			require.Equal(t, before+1, store.lookups, "possible path grant requires exactly one object lookup")
		})
	}
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "object-classification", Statement: model.Statements{
		{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*"},
		{Effect: model.StatementEffectDeny, Action: []string{permissions.ReadObjectAction}, Resource: "*", Condition: map[string]map[string][]string{"StringLike": {"lakefs:ObjectMetadata/dcs:cls": {"S"}}}},
	}}, true))
	before := store.lookups
	recorder := httptest.NewRecorder()
	f.controller.StatObject(recorder, f.request(t, http.MethodGet, "S"), f.repository, "main", apigen.StatObjectParams{Path: "source"})
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.Equal(t, before+1, store.lookups, "matching path Allow must not bypass metadata Deny")
}

func TestObjectMetadataShortCircuitPolicyFailure(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	f.controller.Auth = &metadataPolicyFailure{Service: f.controller.Auth}
	recorder := httptest.NewRecorder()
	f.controller.GetObject(recorder, f.request(t, http.MethodGet, "S"), f.repository, "main", apigen.GetObjectParams{Path: "source"})
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Zero(t, store.lookups)
}
