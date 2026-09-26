package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func policyVariableObjectStatements(repository string) model.Statements {
	return model.Statements{
		{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: permissions.ObjectArn(repository, "${aws:PrincipalTag/clr}/*"),
			Condition: map[string]map[string][]string{auth.OperatorNameStringEquals: {"lakefs:ObjectMetadata/dcs:cls": {"${aws:PrincipalTag/clr}"}}}},
		{Effect: model.StatementEffectAllow, Action: []string{permissions.WriteObjectAction}, Resource: permissions.ObjectArn(repository, "${aws:PrincipalTag/clr}/*")},
	}
}

func TestPolicyVariablesRESTObjectReadPaths(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	f.createObject(t, "S/source", catalog.Metadata{"dcs:cls": "S"})
	f.createObject(t, "S/restricted", catalog.Metadata{"dcs:cls": "TS"})
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "object-classification", Statement: policyVariableObjectStatements(f.repository)}, true))
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	for _, operation := range []struct {
		name    string
		method  string
		status  int
		handler func(http.ResponseWriter, *http.Request, string)
	}{
		{"get", http.MethodGet, http.StatusOK, func(w http.ResponseWriter, r *http.Request, path string) {
			f.controller.GetObject(w, r, f.repository, "main", apigen.GetObjectParams{Path: path})
		}},
		{"head", http.MethodHead, http.StatusOK, func(w http.ResponseWriter, r *http.Request, path string) {
			f.controller.HeadObject(w, r, f.repository, "main", apigen.HeadObjectParams{Path: path})
		}},
		{"stat", http.MethodGet, http.StatusOK, func(w http.ResponseWriter, r *http.Request, path string) {
			f.controller.StatObject(w, r, f.repository, "main", apigen.StatObjectParams{Path: path})
		}},
		{"presigned get", http.MethodGet, http.StatusFound, func(w http.ResponseWriter, r *http.Request, path string) {
			f.controller.GetObject(w, r, f.repository, "main", apigen.GetObjectParams{Path: path, Presign: swag.Bool(true)})
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, test := range []struct {
				name      string
				clearance string
				path      string
				allowed   bool
				lookups   int
			}{
				{"matching resource and metadata", "S", "S/source", true, 1},
				{"wrong tag", "U", "S/source", false, 0},
				{"missing tag", "", "S/source", false, 0},
				{"wrong path", "S", "U/source", false, 0},
				{"metadata mismatch", "S", "S/restricted", false, 1},
			} {
				t.Run(test.name, func(t *testing.T) {
					before := store.lookups
					recorder := httptest.NewRecorder()
					request := f.request(t, operation.method, test.clearance)
					request.Header.Set("X-Amz-Meta-Dcs:Cls", "S")
					operation.handler(recorder, request, test.path)
					require.Equal(t, before+test.lookups, store.lookups, "candidate matching must use the same resource expansion as final authorization")
					if test.allowed {
						require.Equal(t, operation.status, recorder.Code, recorder.Body.String())
						return
					}
					require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
					require.Empty(t, recorder.Header().Get("Location"))
					require.NotContains(t, recorder.Body.String(), metadataSignedURLPrefix)
					require.NotContains(t, recorder.Body.String(), "contents of ")
					if operation.method == http.MethodHead {
						require.Empty(t, recorder.Body.String())
						require.Empty(t, recorder.Header().Get("ETag"))
					}
				})
			}
		})
	}
}

func TestPolicyVariablesRESTCopy(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	f.createObject(t, "S/source", catalog.Metadata{"dcs:cls": "S"})
	f.createObject(t, "S/restricted", catalog.Metadata{"dcs:cls": "TS"})
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "object-classification", Statement: policyVariableObjectStatements(f.repository)}, true))
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	for _, test := range []struct {
		name        string
		clearance   string
		source      string
		destination string
		status      int
		lookups     int
	}{
		{"wrong tag", "U", "S/source", "S/wrong-tag", http.StatusUnauthorized, 0},
		{"wrong source path", "S", "U/source", "S/wrong-source", http.StatusUnauthorized, 0},
		{"wrong destination path", "S", "S/source", "U/copied", http.StatusUnauthorized, 0},
		{"metadata mismatch", "S", "S/restricted", "S/wrong-metadata", http.StatusUnauthorized, 1},
		{"allowed", "S", "S/source", "S/copied", http.StatusCreated, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := store.lookups
			recorder := httptest.NewRecorder()
			f.controller.CopyObject(recorder, f.request(t, http.MethodPost, test.clearance), apigen.CopyObjectJSONRequestBody{SrcPath: test.source}, f.repository, "main", apigen.CopyObjectParams{DestPath: test.destination})
			require.Equal(t, test.status, recorder.Code, recorder.Body.String())
			require.Equal(t, before+test.lookups, store.lookups, "copy must read only the authorized source snapshot")
			entry, err := f.controller.Catalog.GetEntry(t.Context(), f.repository, "main", test.destination, catalog.GetEntryParams{})
			if test.status == http.StatusCreated {
				require.NoError(t, err)
				require.Equal(t, "S", entry.Metadata["dcs:cls"])
			} else {
				require.ErrorIs(t, err, graveler.ErrNotFound)
			}
		})
	}
}

func TestPolicyVariablesRESTMultipartCopyDeniedBeforeStorage(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	f.createObject(t, "S/restricted", catalog.Metadata{"dcs:cls": "TS"})
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "object-classification", Statement: policyVariableObjectStatements(f.repository)}, true))
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	for _, test := range []struct {
		name      string
		clearance string
		lookups   int
	}{{"wrong tag", "U", 0}, {"source metadata mismatch", "S", 1}} {
		t.Run(test.name, func(t *testing.T) {
			before := store.lookups
			recorder := httptest.NewRecorder()
			f.controller.UploadPartCopy(recorder, f.request(t, http.MethodPut, test.clearance), apigen.UploadPartCopyJSONRequestBody{
				UploadPartFrom: apigen.UploadPartFrom{PhysicalAddress: "unused-address"},
				CopySource:     apigen.CopyPartSource{Repository: f.repository, Ref: "main", Path: "S/restricted"},
			}, f.repository, "main", "unused-upload", 1, apigen.UploadPartCopyParams{Path: "S/copied"})
			require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
			require.Equal(t, before+test.lookups, store.lookups)
			require.Empty(t, recorder.Header().Get("ETag"))
		})
	}
}

func TestPolicyVariablesRESTCopyDestinationCannotUseSourceMetadata(t *testing.T) {
	f := newMetadataAuthorizationFixture(t)
	f.createObject(t, "S/source", catalog.Metadata{"dcs:cls": "S"})
	statements := policyVariableObjectStatements(f.repository)
	statements[1].Condition = map[string]map[string][]string{auth.OperatorNameStringEquals: {"lakefs:ObjectMetadata/dcs:cls": {"${aws:PrincipalTag/clr}"}}}
	require.NoError(t, f.controller.Auth.WritePolicy(t.Context(), &model.Policy{DisplayName: "object-classification", Statement: statements}, true))
	store := &metadataLookupStore{Store: f.controller.Catalog.Store}
	f.controller.Catalog.Store = store
	recorder := httptest.NewRecorder()
	request := f.request(t, http.MethodPost, "S")
	request.Header.Set("X-Amz-Meta-Dcs:Cls", "S")
	f.controller.CopyObject(recorder, request, apigen.CopyObjectJSONRequestBody{SrcPath: "S/source"}, f.repository, "main", apigen.CopyObjectParams{DestPath: "S/copied"})
	require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
	require.Equal(t, 1, store.lookups, "source candidate passes; source or request metadata cannot satisfy destination conditions")
	_, err := f.controller.Catalog.GetEntry(t.Context(), f.repository, "main", "S/copied", catalog.GetEntryParams{})
	require.ErrorIs(t, err, graveler.ErrNotFound)
}
