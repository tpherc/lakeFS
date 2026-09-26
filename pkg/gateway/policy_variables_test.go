package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/gateway/operations"
	gatewaypath "github.com/treeverse/lakefs/pkg/gateway/path"
	"github.com/treeverse/lakefs/pkg/permissions"
	"github.com/treeverse/lakefs/pkg/upload"
)

type policyVariableGatewayAuth struct {
	*objectMetadataAuth
}

func (s *policyVariableGatewayAuth) Authorize(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	s.called = true
	assertPolicyVariableWriteMetadataEmpty(s.t, req.RequiredPermissions)
	policies, err := auth.AuthorizationPolicies(ctx, req, s.ListEffectivePolicies)
	if err != nil {
		return nil, err
	}
	result := auth.CheckRequestPermissions(auth.WithRequestConditionContext(ctx, req.ClientIP), req, policies, &auth.MissingPermissions{})
	return &auth.AuthorizationResponse{Allowed: result == auth.CheckAllow}, nil
}

func assertPolicyVariableWriteMetadataEmpty(t *testing.T, node permissions.Node) {
	t.Helper()
	if node.Permission.Action == permissions.WriteObjectAction {
		require.Empty(t, node.Permission.ObjectMetadata, "source metadata must not enter destination authorization")
	}
	for _, child := range node.Nodes {
		assertPolicyVariableWriteMetadataEmpty(t, child)
	}
}

type policyVariableGatewayFixture struct {
	store   *objectMetadataStore
	blocks  *objectMetadataBlocks
	service *policyVariableGatewayAuth
}

func (f *policyVariableGatewayFixture) serve(t *testing.T, request *http.Request, handler operations.PathOperationHandler, path string, tags principaltags.Tags) *httptest.ResponseRecorder {
	t.Helper()
	c := &catalog.Catalog{Store: f.store, BlockAdapter: f.blocks, PathProvider: upload.DefaultPathProvider}
	op := &operations.Operation{Catalog: c, BlockStore: f.blocks, MultipartTracker: &objectMetadataMultipart{}, Incr: func(_, _, _, _ string) {}}
	ctx := auth.WithPrincipalTags(auth.WithUser(request.Context(), &model.User{Username: "alice"}), tags)
	for key, value := range map[contextKey]any{
		ContextKeyOperation: op, ContextKeyRepository: &catalog.Repository{Name: "destination", StorageNamespace: "mem://destination"},
		ContextKeyRef: "main", ContextKeyPath: path, ContextKeyMatchedHost: false,
	} {
		ctx = context.WithValue(ctx, key, value)
	}
	recorder := httptest.NewRecorder()
	PathOperationHandler(&ServerContext{catalog: c, authService: f.service}, handler).ServeHTTP(recorder, request.WithContext(ctx))
	return recorder
}

func policyVariableGatewayPolicies() []*model.Policy {
	return []*model.Policy{{Statement: model.Statements{
		{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn("*", "${aws:PrincipalTag/clr}/*"),
			Condition: map[string]map[string][]string{auth.OperatorNameStringEquals: {"lakefs:ObjectMetadata/dcs:cls": {"${aws:PrincipalTag/clr}"}}}},
		{Effect: model.StatementEffectAllow, Action: []string{permissions.WriteObjectAction}, Resource: permissions.ObjectArn("destination", "${aws:PrincipalTag/clr}/*")},
	}}}
}

func TestPolicyVariablesGatewayObjectPaths(t *testing.T) {
	t.Parallel()
	for _, operation := range []struct {
		name    string
		method  string
		query   string
		copy    bool
		handler operations.PathOperationHandler
	}{
		{"get", http.MethodGet, "", false, &operations.GetObject{}},
		{"head", http.MethodHead, "", false, &operations.HeadObject{}},
		{"copy", http.MethodPut, "", true, &operations.PutObject{}},
		{"multipart copy", http.MethodPut, "?uploadId=upload&partNumber=1", true, &operations.PutObject{}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, test := range []struct {
				name           string
				clearance      string
				classification string
				path           string
				status         int
				lookups        int
			}{
				{"allowed", "S", "S", "S/file", http.StatusOK, 1},
				{"metadata mismatch", "S", "TS", "S/file", http.StatusForbidden, 1},
				{"wrong tag", "U", "S", "S/file", http.StatusForbidden, 0},
				{"missing tag", "", "S", "S/file", http.StatusForbidden, 0},
				{"wrong path", "S", "S", "U/file", http.StatusForbidden, 0},
			} {
				t.Run(test.name, func(t *testing.T) {
					fixture := &policyVariableGatewayFixture{
						store: &objectMetadataStore{t: t, entry: metadataGatewayEntry(test.classification)}, blocks: &objectMetadataBlocks{},
						service: &policyVariableGatewayAuth{objectMetadataAuth: &objectMetadataAuth{t: t, policies: policyVariableGatewayPolicies()}},
					}
					destinationPath := test.path
					if operation.copy {
						destinationPath = "S/copied"
					}
					request := httptest.NewRequest(operation.method, "/destination/main/"+destinationPath+operation.query, nil)
					if operation.copy {
						request.Header.Set(operations.CopySourceHeader, "/source/release/"+test.path)
					}
					request.Header.Set("X-Amz-Meta-Dcs:Cls", "S")
					request.Header.Set("X-Amz-Metadata-Directive", "REPLACE")
					tags := principaltags.Tags{}
					if test.clearance != "" {
						tags["clr"] = test.clearance
					}
					recorder := fixture.serve(t, request, operation.handler, destinationPath, tags)
					require.Equal(t, test.status, recorder.Code, recorder.Body.String())
					require.Equal(t, 1, fixture.service.policyReads)
					require.Len(t, fixture.store.reads, test.lookups)
					require.Equal(t, test.lookups != 0, fixture.service.called, "impossible grants must reject before final authorization")
					if test.status != http.StatusOK {
						require.Empty(t, fixture.blocks.reads)
						require.Nil(t, fixture.store.written)
						require.NotContains(t, recorder.Body.String(), "authorized bytes")
						return
					}
					expected := gatewaypath.ResolvedAbsolutePath{Repo: "destination", Reference: "main", Path: test.path}
					if operation.copy {
						expected.Repo, expected.Reference = "source", "release"
					}
					require.Equal(t, []gatewaypath.ResolvedAbsolutePath{expected}, fixture.store.reads)
					if operation.method == http.MethodHead {
						require.Empty(t, fixture.blocks.reads)
						require.Equal(t, []string{`"checksum-S"`}, recorder.Header()["ETag"])
					} else {
						require.Len(t, fixture.blocks.reads, 1)
						require.Equal(t, "authorized-S", fixture.blocks.reads[0].Identifier)
					}
				})
			}
		})
	}
}

func TestPolicyVariablesGatewayCopyDestinationCannotUseSourceMetadata(t *testing.T) {
	t.Parallel()
	for _, query := range []string{"", "?uploadId=upload&partNumber=1"} {
		t.Run(query, func(t *testing.T) {
			policies := policyVariableGatewayPolicies()
			policies[0].Statement[1].Condition = map[string]map[string][]string{
				auth.OperatorNameStringEquals: {"lakefs:ObjectMetadata/dcs:cls": {"${aws:PrincipalTag/clr}"}},
			}
			fixture := &policyVariableGatewayFixture{
				store: &objectMetadataStore{t: t, entry: metadataGatewayEntry("S")}, blocks: &objectMetadataBlocks{},
				service: &policyVariableGatewayAuth{objectMetadataAuth: &objectMetadataAuth{t: t, policies: policies}},
			}
			request := httptest.NewRequest(http.MethodPut, "/destination/main/S/copied"+query, nil)
			request.Header.Set(operations.CopySourceHeader, "/source/release/S/file")
			request.Header.Set("X-Amz-Meta-Dcs:Cls", "S")
			request.Header.Set("X-Amz-Metadata-Directive", "REPLACE")
			recorder := fixture.serve(t, request, &operations.PutObject{}, "S/copied", principaltags.Tags{"clr": "S"})
			require.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
			require.Len(t, fixture.store.reads, 1, "source candidate passes before destination condition fails")
			require.True(t, fixture.service.called)
			require.Equal(t, 1, fixture.service.policyReads)
			require.Empty(t, fixture.blocks.reads)
			require.Nil(t, fixture.store.written)
		})
	}
}
