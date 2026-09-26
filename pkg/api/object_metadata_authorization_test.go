package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/permissions"
	"github.com/treeverse/lakefs/pkg/stats"
)

const metadataSignedURLPrefix = "https://signed.example/"

// The memory adapter has no presigner. Keep its real storage operations and
// return recognizable signed URLs so authorization failures cannot hide a leak.
type metadataPresigningAdapter struct {
	block.Adapter
}

func (a metadataPresigningAdapter) GetPreSignedURL(_ context.Context, _ block.ObjectPointer, _ block.PreSignMode, filename string) (string, time.Time, error) {
	return metadataSignedURLPrefix + url.PathEscape(filename), time.Unix(2_000_000_000, 0), nil
}

type metadataAuthorizationFixture struct {
	controller *api.Controller
	user       *model.User
	repository string
	namespace  string
}

func newMetadataAuthorizationFixture(t *testing.T) *metadataAuthorizationFixture {
	t.Helper()
	_, deps := setupHandler(t)
	service := authacl.NewAuthService(kvtest.GetStore(t.Context(), t), crypt.NewSecretStore([]byte("metadata-test-secret")), authparams.ServiceCache{}, true)
	user := &model.User{Username: "metadata-reader"}
	_, err := service.CreateUser(t.Context(), user)
	require.NoError(t, err)
	statements := model.Statements{{
		Effect:   model.StatementEffectAllow,
		Action:   []string{permissions.ListObjectsAction, permissions.WriteObjectAction},
		Resource: "*",
	}}
	classifications := []string{"U", "R", "S", "TS"}
	for rank, clearance := range classifications {
		statements = append(statements, model.Statement{
			Effect:   model.StatementEffectAllow,
			Action:   []string{permissions.ReadObjectAction},
			Resource: "*",
			Condition: map[string]map[string][]string{
				"StringLike": {
					"aws:PrincipalTag/clr":          {clearance},
					"lakefs:ObjectMetadata/dcs:cls": classifications[:rank+1],
				},
			},
		})
	}
	policy := &model.Policy{DisplayName: "object-classification", Statement: statements}
	require.NoError(t, service.WritePolicy(t.Context(), policy, false))
	require.NoError(t, service.AttachPolicyToUser(t.Context(), policy.DisplayName, user.Username))
	fixture := &metadataAuthorizationFixture{
		controller: &api.Controller{
			Catalog: deps.catalog, Auth: service, BlockAdapter: metadataPresigningAdapter{deps.blocks},
			Logger: logging.Dummy(), Collector: &stats.NullCollector{},
		},
		user: user, repository: testUniqueRepoName(), namespace: onBlock(deps, "classification-test"),
	}
	_, err = deps.catalog.CreateRepository(t.Context(), fixture.repository, config.SingleBlockstoreID, fixture.namespace, "main", false)
	require.NoError(t, err)
	return fixture
}

func (f *metadataAuthorizationFixture) createObject(t *testing.T, path string, metadata catalog.Metadata) {
	t.Helper()
	content := "contents of " + path
	_, err := f.controller.BlockAdapter.Put(t.Context(), block.ObjectPointer{
		StorageID: config.SingleBlockstoreID, StorageNamespace: f.namespace,
		IdentifierType: block.IdentifierTypeRelative, Identifier: path,
	}, int64(len(content)), strings.NewReader(content), block.PutOpts{})
	require.NoError(t, err)
	require.NoError(t, f.controller.Catalog.CreateEntry(t.Context(), f.repository, "main", catalog.DBEntry{
		Path: path, PhysicalAddress: path, AddressType: catalog.AddressTypeRelative,
		Size: int64(len(content)), Checksum: "test-checksum", CreationDate: time.Now(),
		ContentType: "text/plain", Metadata: metadata,
	}))
}

func (f *metadataAuthorizationFixture) request(t *testing.T, method, clearance string) *http.Request {
	t.Helper()
	tags := principaltags.Tags{}
	if clearance != "" {
		tags["clr"] = clearance
	}
	ctx := auth.WithPrincipalTags(auth.WithUser(t.Context(), f.user), tags)
	return httptest.NewRequest(method, "http://lakefs.example/", nil).WithContext(ctx)
}

func TestObjectMetadataAuthorizationClearance(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	classifications := []string{"U", "R", "S", "TS"}
	for _, classification := range classifications {
		f.createObject(t, classification+".txt", catalog.Metadata{"dcs:cls": classification})
	}
	for clearanceRank, clearance := range classifications {
		for classificationRank, classification := range classifications {
			t.Run(clearance+" reads "+classification, func(t *testing.T) {
				recorder := httptest.NewRecorder()
				f.controller.StatObject(recorder, f.request(t, http.MethodGet, clearance), f.repository, "main", apigen.StatObjectParams{
					Path: classification + ".txt", UserMetadata: swag.Bool(false),
				})
				if classificationRank <= clearanceRank {
					require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				} else {
					require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
				}
			})
		}
	}
	for _, tc := range []struct {
		name      string
		metadata  catalog.Metadata
		clearance string
	}{
		{name: "missing classification", clearance: "TS"},
		{name: "metadata key case differs", metadata: catalog.Metadata{"DCS:CLS": "U"}, clearance: "TS"},
		{name: "classification value case differs", metadata: catalog.Metadata{"dcs:cls": "u"}, clearance: "TS"},
		{name: "missing principal clearance", metadata: catalog.Metadata{"dcs:cls": "U"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.createObject(t, tc.name, tc.metadata)
			recorder := httptest.NewRecorder()
			f.controller.StatObject(recorder, f.request(t, http.MethodGet, tc.clearance), f.repository, "main", apigen.StatObjectParams{Path: tc.name})
			require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
		})
	}
}

func TestObjectMetadataAuthorizationReadPaths(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	const objectPath = "secret.txt"
	f.createObject(t, objectPath, catalog.Metadata{"dcs:cls": "S"})
	for _, tc := range []struct {
		name    string
		method  string
		allowed int
		handle  func(http.ResponseWriter, *http.Request)
	}{
		{name: "stat", method: http.MethodGet, allowed: http.StatusOK, handle: func(w http.ResponseWriter, r *http.Request) {
			f.controller.StatObject(w, r, f.repository, "main", apigen.StatObjectParams{Path: objectPath, UserMetadata: swag.Bool(false)})
		}},
		{name: "stat presign", method: http.MethodGet, allowed: http.StatusOK, handle: func(w http.ResponseWriter, r *http.Request) {
			f.controller.StatObject(w, r, f.repository, "main", apigen.StatObjectParams{Path: objectPath, Presign: swag.Bool(true), UserMetadata: swag.Bool(false)})
		}},
		{name: "get", method: http.MethodGet, allowed: http.StatusOK, handle: func(w http.ResponseWriter, r *http.Request) {
			f.controller.GetObject(w, r, f.repository, "main", apigen.GetObjectParams{Path: objectPath})
		}},
		{name: "get presign", method: http.MethodGet, allowed: http.StatusFound, handle: func(w http.ResponseWriter, r *http.Request) {
			f.controller.GetObject(w, r, f.repository, "main", apigen.GetObjectParams{Path: objectPath, Presign: swag.Bool(true)})
		}},
		{name: "head", method: http.MethodHead, allowed: http.StatusOK, handle: func(w http.ResponseWriter, r *http.Request) {
			f.controller.HeadObject(w, r, f.repository, "main", apigen.HeadObjectParams{Path: objectPath})
		}},
		{name: "underlying properties", method: http.MethodGet, allowed: http.StatusOK, handle: func(w http.ResponseWriter, r *http.Request) {
			f.controller.GetUnderlyingProperties(w, r, f.repository, "main", apigen.GetUnderlyingPropertiesParams{Path: objectPath})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied := httptest.NewRecorder()
			tc.handle(denied, f.request(t, tc.method, "R"))
			require.Equal(t, http.StatusUnauthorized, denied.Code, denied.Body.String())
			require.Empty(t, denied.Header().Get("Location"))
			require.NotContains(t, denied.Body.String(), metadataSignedURLPrefix)
			require.NotContains(t, denied.Body.String(), "contents of ")
			if tc.method == http.MethodHead {
				require.Empty(t, denied.Body.String())
				require.Empty(t, denied.Header().Get("ETag"))
			}
			allowed := httptest.NewRecorder()
			tc.handle(allowed, f.request(t, tc.method, "S"))
			require.Equal(t, tc.allowed, allowed.Code, allowed.Body.String())
		})
	}
}

func TestObjectMetadataAuthorizationListPresign(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	for _, classification := range []string{"U", "R", "S", "TS"} {
		f.createObject(t, classification+".txt", catalog.Metadata{"dcs:cls": classification})
	}
	recorder := httptest.NewRecorder()
	f.controller.ListObjects(recorder, f.request(t, http.MethodGet, "R"), f.repository, "main", apigen.ListObjectsParams{
		Presign: swag.Bool(true), UserMetadata: swag.Bool(false),
	})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var result apigen.ObjectStatsList
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &result))
	require.Len(t, result.Results, 2)
	require.Equal(t, "R.txt", result.Results[0].Path)
	require.Equal(t, "U.txt", result.Results[1].Path)
	for _, object := range result.Results {
		require.Nil(t, object.Metadata, object.Path)
		require.Equal(t, metadataSignedURLPrefix+object.Path, object.PhysicalAddress)
		require.NotNil(t, object.PhysicalAddressExpiry)
	}
}

func TestObjectMetadataAuthorizationReferenceAndCopy(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	const objectPath = "README.txt"
	f.createObject(t, objectPath, catalog.Metadata{"dcs:cls": "S"})
	commit, err := f.controller.Catalog.Commit(t.Context(), f.repository, "main", "classify secret", f.user.Username, nil, nil, nil, false)
	require.NoError(t, err)
	require.NoError(t, f.controller.Catalog.UpdateEntryUserMetadata(t.Context(), f.repository, "main", objectPath, map[string]string{"dcs:cls": "U"}))
	for _, tc := range []struct {
		name   string
		ref    string
		status int
	}{
		{name: "staged metadata", ref: "main", status: http.StatusOK},
		{name: "committed metadata", ref: commit.Reference, status: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			f.controller.StatObject(recorder, f.request(t, http.MethodGet, "U"), f.repository, tc.ref, apigen.StatObjectParams{Path: objectPath})
			require.Equal(t, tc.status, recorder.Code, recorder.Body.String())
		})
	}

	denied := httptest.NewRecorder()
	f.controller.CopyObject(denied, f.request(t, http.MethodPost, "U"), apigen.CopyObjectJSONRequestBody{
		SrcPath: objectPath, SrcRef: &commit.Reference,
	}, f.repository, "main", apigen.CopyObjectParams{DestPath: "denied-copy.txt"})
	require.Equal(t, http.StatusUnauthorized, denied.Code, denied.Body.String())
	_, err = f.controller.Catalog.GetEntry(t.Context(), f.repository, "main", "denied-copy.txt", catalog.GetEntryParams{})
	require.ErrorIs(t, err, graveler.ErrNotFound)

	multipartDenied := httptest.NewRecorder()
	f.controller.UploadPartCopy(multipartDenied, f.request(t, http.MethodPut, "U"), apigen.UploadPartCopyJSONRequestBody{
		UploadPartFrom: apigen.UploadPartFrom{PhysicalAddress: "unused-address"},
		CopySource: apigen.CopyPartSource{
			Repository: f.repository, Ref: commit.Reference, Path: objectPath,
		},
	}, f.repository, "main", "unused-upload", 1, apigen.UploadPartCopyParams{Path: "denied-multipart.txt"})
	require.Equal(t, http.StatusUnauthorized, multipartDenied.Code, multipartDenied.Body.String())
	require.Empty(t, multipartDenied.Header().Get("ETag"))

	allowed := httptest.NewRecorder()
	f.controller.CopyObject(allowed, f.request(t, http.MethodPost, "U"), apigen.CopyObjectJSONRequestBody{
		SrcPath: objectPath,
	}, f.repository, "main", apigen.CopyObjectParams{DestPath: "allowed-copy.txt"})
	require.Equal(t, http.StatusCreated, allowed.Code, allowed.Body.String())
	entry, err := f.controller.Catalog.GetEntry(t.Context(), f.repository, "main", "allowed-copy.txt", catalog.GetEntryParams{})
	require.NoError(t, err)
	require.Equal(t, "U", entry.Metadata["dcs:cls"])
}
