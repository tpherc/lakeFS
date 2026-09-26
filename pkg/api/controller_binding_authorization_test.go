package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/permissions"
)

type bindingDenyAuthService struct {
	auth.Service
	requests []auth.AuthorizationRequest
}

func (s *bindingDenyAuthService) Authorize(_ context.Context, request *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	s.requests = append(s.requests, *request)
	return &auth.AuthorizationResponse{Allowed: false, Error: auth.ErrInsufficientPermissions}, nil
}

func bindingAuthorizationRequest(t *testing.T) *http.Request {
	t.Helper()
	ctx := auth.WithUser(t.Context(), &model.User{Username: "restricted-writer"})
	return httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
}

// These tests record the current permission contract. They do not establish that
// allowing destination writers to select every configured backend is appropriate
// for a particular deployment.
func TestControllerBindingDestinationAuthorization(t *testing.T) {
	const sourceAddress = "s3://shared-bucket/same-key"
	handlers := []struct {
		name   string
		invoke func(*api.Controller, http.ResponseWriter, *http.Request, *string)
	}{
		{"link", func(controller *api.Controller, w http.ResponseWriter, r *http.Request, storageID *string) {
			controller.LinkPhysicalAddress(w, r, apigen.LinkPhysicalAddressJSONRequestBody{
				Staging:  apigen.StagingLocation{PhysicalAddress: swag.String(sourceAddress), StorageId: storageID},
				Checksum: "etag", SizeBytes: 4,
			}, "destination", "main", apigen.LinkPhysicalAddressParams{Path: "view/object"})
		}},
		{"stage", func(controller *api.Controller, w http.ResponseWriter, r *http.Request, storageID *string) {
			controller.StageObject(w, r, apigen.StageObjectJSONRequestBody{
				PhysicalAddress: sourceAddress, StorageId: storageID, Checksum: "etag", SizeBytes: 4,
			}, "destination", "main", apigen.StageObjectParams{Path: "view/object"})
		}},
	}
	ids := []struct {
		name  string
		value *string
	}{
		{"omitted", nil}, {"empty", swag.String("")}, {"home", swag.String("home")},
		{"source-a", swag.String("source-a")}, {"source-b", swag.String("source-b")},
		{"unknown", swag.String("unknown")},
	}
	expected := permissions.Node{Permission: permissions.Permission{
		Action: permissions.WriteObjectAction, Resource: permissions.ObjectArn("destination", "view/object"),
	}}
	for _, handler := range handlers {
		t.Run(handler.name, func(t *testing.T) {
			for _, id := range ids {
				t.Run(id.name, func(t *testing.T) {
					service := &bindingDenyAuthService{}
					// A denied request must return before accessing catalog, configuration or storage.
					controller := &api.Controller{Auth: service}
					response := httptest.NewRecorder()
					handler.invoke(controller, response, bindingAuthorizationRequest(t), id.value)
					require.Equal(t, http.StatusUnauthorized, response.Code)
					require.Contains(t, response.Body.String(), auth.ErrInsufficientPermissions.Error())
					require.Len(t, service.requests, 1)
					require.Equal(t, "restricted-writer", service.requests[0].Username)
					require.Equal(t, expected, service.requests[0].RequiredPermissions)
				})
			}
		})
	}
}

func TestControllerBindingImportAuthorizationUsesSourceURI(t *testing.T) {
	const sourceAddress = "s3://shared-bucket/same-prefix/"
	expected := permissions.Node{
		Type: permissions.NodeTypeAnd,
		Nodes: []permissions.Node{
			{Permission: permissions.Permission{Action: permissions.WriteObjectAction, Resource: permissions.BranchArn("destination", "main")}},
			{Permission: permissions.Permission{Action: permissions.CreateCommitAction, Resource: permissions.BranchArn("destination", "main")}},
			{Permission: permissions.Permission{Action: permissions.ImportFromStorageAction, Resource: permissions.StorageNamespace(sourceAddress)}},
			{Permission: permissions.Permission{Action: permissions.WriteObjectAction, Resource: permissions.ObjectArn("destination", "view/")}},
		},
	}
	service := &bindingDenyAuthService{}
	controller := &api.Controller{Auth: service}
	for _, storageID := range []string{"", "source-a", "source-b", "unknown"} {
		response := httptest.NewRecorder()
		controller.ImportStart(response, bindingAuthorizationRequest(t), apigen.ImportStartJSONRequestBody{
			Paths:  []apigen.ImportLocation{{Type: "common_prefix", Path: sourceAddress, Destination: "view/", StorageId: swag.String(storageID)}},
			Commit: apigen.CommitCreation{Message: "Import selected backend"},
		}, "destination", "main")
		require.Equal(t, http.StatusUnauthorized, response.Code, "source ID %q cannot bypass denial", storageID)
	}
	require.Len(t, service.requests, 4)
	for _, request := range service.requests {
		// Colliding native URIs produce the same source permission resource even
		// when their configured IDs select different endpoints or credentials.
		require.Equal(t, expected, request.RequiredPermissions)
	}
}
