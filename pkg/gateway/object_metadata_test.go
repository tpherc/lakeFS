package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/gateway/multipart"
	"github.com/treeverse/lakefs/pkg/gateway/operations"
	gatewaypath "github.com/treeverse/lakefs/pkg/gateway/path"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/permissions"
	"github.com/treeverse/lakefs/pkg/upload"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestObjectMetadataAuthorization(t *testing.T) {
	t.Parallel()
	operationsToTest := []struct {
		name       string
		method     string
		query      string
		copySource string
		userAgent  string
		handler    operations.PathOperationHandler
		status     int
	}{
		{name: "get", method: http.MethodGet, handler: &operations.GetObject{}, status: http.StatusOK},
		{name: "head", method: http.MethodHead, handler: &operations.HeadObject{}, status: http.StatusOK},
		{name: "presigned redirect", method: http.MethodGet, userAgent: "s3RedirectionSupport", handler: &operations.GetObject{}, status: http.StatusTemporaryRedirect},
		{name: "copy", method: http.MethodPut, copySource: "/source/release/file", handler: &operations.PutObject{}, status: http.StatusOK},
		{name: "copy part", method: http.MethodPut, query: "?uploadId=upload&partNumber=1", copySource: "/source/release/file", handler: &operations.PutObject{}, status: http.StatusOK},
		{name: "copy same resource", method: http.MethodPut, copySource: "/destination/release/file", handler: &operations.PutObject{}, status: http.StatusOK},
	}
	for _, operation := range operationsToTest {
		t.Run(operation.name, func(t *testing.T) {
			for _, classification := range []string{"S", "TS", ""} {
				t.Run("classification="+classification, func(t *testing.T) {
					store := &objectMetadataStore{t: t, entry: metadataGatewayEntry(classification)}
					blocks := &objectMetadataBlocks{}
					service := &objectMetadataAuth{t: t, policies: objectMetadataPolicies(), afterAuthorize: func() {
						// A concurrent branch change must not replace the entry whose metadata was authorized.
						store.entry = metadataGatewayEntry("TS")
					}}
					req := httptest.NewRequest(operation.method, "/destination/main/file"+operation.query, nil)
					req.Header.Set(operations.CopySourceHeader, operation.copySource)
					req.Header.Set("User-Agent", operation.userAgent)
					// Client-supplied replacement metadata cannot satisfy source read authorization.
					req.Header.Set("X-Amz-Meta-Dcs:Cls", "S")
					req.Header.Set("X-Amz-Metadata-Directive", "REPLACE")
					recorder := serveMetadataGateway(t, req, operation.handler, store, blocks, service)
					require.Equal(t, 1, service.policyReads, "load one policy snapshot for preliminary and final authorization")
					expectedPath := gatewaypath.ResolvedAbsolutePath{Repo: "destination", Reference: "main", Path: "file"}
					if operation.copySource != "" {
						var err error
						expectedPath, err = gatewaypath.ResolveAbsolutePath(operation.copySource)
						require.NoError(t, err)
					}
					require.Equal(t, []gatewaypath.ResolvedAbsolutePath{expectedPath}, store.reads, "load the exact source only once")
					if classification != "S" {
						require.Equal(t, http.StatusForbidden, recorder.Code)
						require.Empty(t, blocks.reads, "denied requests must not read, copy, or presign bytes")
						require.Nil(t, store.written)
						return
					}
					require.Equal(t, operation.status, recorder.Code, recorder.Body.String())
					for _, read := range blocks.reads {
						require.Equal(t, "authorized-S", read.Identifier)
						require.Equal(t, "mem://"+expectedPath.Repo, read.StorageNamespace)
					}
					if operation.name != "head" {
						require.Len(t, blocks.reads, 1)
					}
					if operation.name == "get" {
						require.Equal(t, "authorized bytes", recorder.Body.String())
					}
					if operation.name == "head" {
						require.Equal(t, []string{`"checksum-S"`}, recorder.Header()["ETag"])
					}
				})
			}
		})
	}
}

func TestObjectMetadataLookupFailure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		err      error
		policies []*model.Policy
		status   int
	}{
		{name: "missing denied", err: graveler.ErrNotFound, policies: objectMetadataPolicies(), status: http.StatusForbidden},
		{name: "missing allowed", err: graveler.ErrNotFound, policies: unrestrictedReadPolicy(), status: http.StatusNotFound},
		{name: "lookup error", err: errors.New("catalog unavailable"), policies: unrestrictedReadPolicy(), status: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &objectMetadataStore{t: t, err: test.err}
			blocks := &objectMetadataBlocks{}
			service := &objectMetadataAuth{t: t, policies: test.policies}
			req := httptest.NewRequest(http.MethodGet, "/destination/main/file", nil)
			req.Header.Set("User-Agent", "s3RedirectionSupport")
			recorder := serveMetadataGateway(t, req, &operations.GetObject{}, store, blocks, service)
			require.True(t, service.called, "authorize missing objects before disclosing lookup failure")
			require.Equal(t, test.status, recorder.Code)
			require.Empty(t, blocks.reads)
		})
	}
}

func TestNonObjectReadsDoNotLoadMetadata(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		method  string
		query   string
		handler operations.PathOperationHandler
	}{
		{name: "list parts", method: http.MethodGet, query: "?uploadId=upload", handler: &operations.GetObject{}},
		{name: "upload", method: http.MethodPut, handler: &operations.PutObject{}},
		{name: "upload part", method: http.MethodPut, query: "?uploadId=upload&partNumber=1", handler: &operations.PutObject{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &objectMetadataStore{t: t}
			blocks := &objectMetadataBlocks{}
			// Denial avoids unrelated storage behavior while exercising the real preparation boundary.
			service := &objectMetadataAuth{t: t}
			req := httptest.NewRequest(test.method, "/destination/main/file"+test.query, nil)
			recorder := serveMetadataGateway(t, req, test.handler, store, blocks, service)
			require.Equal(t, http.StatusForbidden, recorder.Code)
			require.True(t, service.called)
			require.Empty(t, store.reads)
			require.Equal(t, 1, service.policyReads, "only final authorization loads policies")
		})
	}
}

func TestObjectMetadataPrecheck(t *testing.T) {
	t.Parallel()
	writePolicy := &model.Policy{Statement: model.Statements{{Effect: "allow", Action: []string{permissions.WriteObjectAction}, Resource: "*"}}}
	for _, test := range []struct {
		name       string
		method     string
		query      string
		copySource string
		policies   []*model.Policy
		policyErr  error
		handler    operations.PathOperationHandler
		status     int
	}{
		{name: "no get allow", method: http.MethodGet, handler: &operations.GetObject{}, status: http.StatusForbidden},
		{name: "no head allow", method: http.MethodHead, handler: &operations.HeadObject{}, status: http.StatusForbidden},
		{name: "copy missing source read", method: http.MethodPut, copySource: "/source/release/file", policies: []*model.Policy{writePolicy}, handler: &operations.PutObject{}, status: http.StatusForbidden},
		{name: "copy missing destination write", method: http.MethodPut, copySource: "/source/release/file", policies: unrestrictedReadPolicy(), handler: &operations.PutObject{}, status: http.StatusForbidden},
		{name: "copy part missing source read", method: http.MethodPut, query: "?uploadId=upload&partNumber=1", copySource: "/source/release/file", policies: []*model.Policy{writePolicy}, handler: &operations.PutObject{}, status: http.StatusForbidden},
		{name: "copy part missing destination write", method: http.MethodPut, query: "?uploadId=upload&partNumber=1", copySource: "/source/release/file", policies: unrestrictedReadPolicy(), handler: &operations.PutObject{}, status: http.StatusForbidden},
		{name: "policy lookup error", method: http.MethodGet, policyErr: errors.New("policy service unavailable"), handler: &operations.GetObject{}, status: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &objectMetadataStore{t: t}
			blocks := &objectMetadataBlocks{}
			service := &objectMetadataAuth{t: t, policies: test.policies, policyErr: test.policyErr}
			req := httptest.NewRequest(test.method, "/destination/main/file"+test.query, nil)
			req.Header.Set(operations.CopySourceHeader, test.copySource)
			recorder := serveMetadataGateway(t, req, test.handler, store, blocks, service)
			require.Equal(t, test.status, recorder.Code, recorder.Body.String())
			require.Equal(t, 1, service.policyReads)
			require.False(t, service.called)
			require.Empty(t, store.reads, "reject impossible permission requests before loading object metadata")
			require.Empty(t, blocks.reads)
		})
	}
}

func TestObjectMetadataConditionalDenyAfterPrecheck(t *testing.T) {
	t.Parallel()
	policies := append(unrestrictedReadPolicy(), &model.Policy{Statement: model.Statements{{
		Effect: "deny", Action: []string{permissions.ReadObjectAction}, Resource: "*",
		Condition: map[string]map[string][]string{"StringLike": {"lakefs:ObjectMetadata/dcs:cls": {"TS"}}},
	}}})
	for _, classification := range []string{"S", "TS"} {
		t.Run(classification, func(t *testing.T) {
			store := &objectMetadataStore{t: t, entry: metadataGatewayEntry(classification)}
			blocks := &objectMetadataBlocks{}
			service := &objectMetadataAuth{t: t, policies: policies}
			recorder := serveMetadataGateway(t, httptest.NewRequest(http.MethodGet, "/destination/main/file", nil), &operations.GetObject{}, store, blocks, service)
			require.Equal(t, 1, service.policyReads)
			require.True(t, service.called, "conditional denial needs the full metadata-aware decision")
			require.Len(t, store.reads, 1)
			if classification == "TS" {
				require.Equal(t, http.StatusForbidden, recorder.Code)
				require.Empty(t, blocks.reads)
			} else {
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Len(t, blocks.reads, 1)
			}
		})
	}
}

func TestObjectMetadataPrecheckUnsupportedPolicyListing(t *testing.T) {
	t.Parallel()
	store := &objectMetadataStore{t: t, entry: metadataGatewayEntry("S")}
	blocks := &objectMetadataBlocks{}
	service := &objectMetadataAuth{t: t, policies: objectMetadataPolicies(), policyErr: auth.ErrNotImplemented}
	recorder := serveMetadataGateway(t, httptest.NewRequest(http.MethodGet, "/destination/main/file", nil), &operations.GetObject{}, store, blocks, service)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, 1, service.policyReads)
	require.True(t, service.called, "an unsupported precheck must preserve final backend authorization")
	require.Len(t, store.reads, 1)
}

func objectMetadataPolicies() []*model.Policy {
	return []*model.Policy{{Statement: model.Statements{
		{Effect: "allow", Action: []string{permissions.WriteObjectAction}, Resource: "*"},
		{Effect: "allow", Action: []string{permissions.ReadObjectAction}, Resource: "*", Condition: map[string]map[string][]string{
			"StringLike": {"lakefs:ObjectMetadata/dcs:cls": {"S"}, "aws:PrincipalTag/clr": {"S"}},
		}},
	}}}
}

func unrestrictedReadPolicy() []*model.Policy {
	return []*model.Policy{{Statement: model.Statements{{Effect: "allow", Action: []string{permissions.ReadObjectAction}, Resource: "*"}}}}
}

func serveMetadataGateway(t *testing.T, req *http.Request, controller operations.PathOperationHandler, store *objectMetadataStore, blocks *objectMetadataBlocks, service *objectMetadataAuth) *httptest.ResponseRecorder {
	t.Helper()
	c := &catalog.Catalog{Store: store, BlockAdapter: blocks, PathProvider: upload.DefaultPathProvider}
	o := &operations.Operation{Catalog: c, BlockStore: blocks, MultipartTracker: &objectMetadataMultipart{}, Incr: func(_, _, _, _ string) {}}
	ctx := auth.WithUser(req.Context(), &model.User{Username: "alice"})
	ctx = auth.WithPrincipalTags(ctx, principaltags.Tags{"clr": "S"})
	for key, value := range map[contextKey]any{
		ContextKeyOperation:   o,
		ContextKeyRepository:  &catalog.Repository{Name: "destination", StorageNamespace: "mem://destination"},
		ContextKeyRef:         "main",
		ContextKeyPath:        "file",
		ContextKeyMatchedHost: false,
	} {
		ctx = context.WithValue(ctx, key, value)
	}
	recorder := httptest.NewRecorder()
	PathOperationHandler(&ServerContext{catalog: c, authService: service}, controller).ServeHTTP(recorder, req.WithContext(ctx))
	return recorder
}

func metadataGatewayEntry(classification string) *catalog.Entry {
	metadata := map[string]string{}
	if classification != "" {
		metadata["dcs:cls"] = classification
	}
	return &catalog.Entry{ETag: "checksum-" + classification, Address: "authorized-" + classification, AddressType: catalog.Entry_RELATIVE, LastModified: timestamppb.New(time.Now()), Metadata: metadata, Size: 16, ContentType: "text/plain"}
}

type objectMetadataStore struct {
	catalog.Store
	t       *testing.T
	entry   *catalog.Entry
	err     error
	reads   []gatewaypath.ResolvedAbsolutePath
	written *graveler.Value
}

func (s *objectMetadataStore) GetRepository(_ context.Context, id graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	return &graveler.RepositoryRecord{RepositoryID: id, Repository: &graveler.Repository{StorageNamespace: graveler.StorageNamespace("mem://" + id), DefaultBranchID: "main"}}, nil
}

func (s *objectMetadataStore) Get(_ context.Context, repository *graveler.RepositoryRecord, ref graveler.Ref, key graveler.Key, _ ...graveler.GetOptionsFunc) (*graveler.Value, error) {
	s.reads = append(s.reads, gatewaypath.ResolvedAbsolutePath{Repo: repository.RepositoryID.String(), Reference: ref.String(), Path: string(key)})
	if s.err != nil {
		return nil, s.err
	}
	require.NotNil(s.t, s.entry)
	return catalog.EntryToValue(s.entry)
}

func (s *objectMetadataStore) GetBranch(context.Context, *graveler.RepositoryRecord, graveler.BranchID) (*graveler.Branch, error) {
	return &graveler.Branch{}, nil
}

func (s *objectMetadataStore) Set(_ context.Context, _ *graveler.RepositoryRecord, _ graveler.BranchID, _ graveler.Key, value graveler.Value, _ ...graveler.SetOptionsFunc) error {
	s.written = &value
	return nil
}

type objectMetadataAuth struct {
	auth.GatewayService
	t              *testing.T
	policies       []*model.Policy
	policyErr      error
	policyReads    int
	afterAuthorize func()
	called         bool
}

func (s *objectMetadataAuth) ListEffectivePolicies(_ context.Context, username string, _ *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	require.Equal(s.t, "alice", username)
	s.policyReads++
	return s.policies, &model.Paginator{}, s.policyErr
}

func (s *objectMetadataAuth) Authorize(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	s.called = true
	var checkWriteMetadata func(permissions.Node)
	checkWriteMetadata = func(node permissions.Node) {
		if node.Permission.Action == permissions.WriteObjectAction {
			require.Empty(s.t, node.Permission.ObjectMetadata, "read-source metadata must not enter write authorization")
		}
		for _, child := range node.Nodes {
			checkWriteMetadata(child)
		}
	}
	checkWriteMetadata(req.RequiredPermissions)
	policies := s.policies
	if !errors.Is(s.policyErr, auth.ErrNotImplemented) {
		var err error
		policies, err = auth.AuthorizationPolicies(ctx, req, s.ListEffectivePolicies)
		if err != nil {
			return nil, err
		}
	}
	ctx = auth.WithRequestConditionContext(ctx, req.ClientIP)
	result := auth.CheckPermissions(ctx, req.RequiredPermissions, req.Username, policies, &auth.MissingPermissions{})
	if s.afterAuthorize != nil {
		s.afterAuthorize()
	}
	return &auth.AuthorizationResponse{Allowed: result == auth.CheckAllow}, nil
}

type objectMetadataBlocks struct {
	block.Adapter
	reads []block.ObjectPointer
}

func (b *objectMetadataBlocks) Get(_ context.Context, object block.ObjectPointer) (io.ReadCloser, error) {
	b.reads = append(b.reads, object)
	return io.NopCloser(strings.NewReader("authorized bytes")), nil
}

func (b *objectMetadataBlocks) GetPreSignedURL(_ context.Context, object block.ObjectPointer, _ block.PreSignMode, _ string) (string, time.Time, error) {
	b.reads = append(b.reads, object)
	return "https://storage.example/authorized-S", time.Now().Add(time.Minute), nil
}

func (b *objectMetadataBlocks) Copy(_ context.Context, source, _ block.ObjectPointer) error {
	b.reads = append(b.reads, source)
	return nil
}

func (b *objectMetadataBlocks) UploadCopyPart(_ context.Context, source, _ block.ObjectPointer, _ string, _ int) (*block.UploadPartResponse, error) {
	b.reads = append(b.reads, source)
	return &block.UploadPartResponse{ETag: "etag"}, nil
}

type objectMetadataMultipart struct{ multipart.Tracker }

func (m *objectMetadataMultipart) Get(context.Context, string) (*multipart.Upload, error) {
	return &multipart.Upload{PhysicalAddress: "multipart-destination"}, nil
}
