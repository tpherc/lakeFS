package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/catalog"
)

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
