package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/permissions"
)

type targetOnlyGCAuth struct {
	auth.Service
	requests []auth.AuthorizationRequest
}

func (s *targetOnlyGCAuth) Authorize(_ context.Context, request *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	s.requests = append(s.requests, *request)
	permission := request.RequiredPermissions.Permission
	allowed := permission.Resource == permissions.RepoArn("owner") &&
		permission.Action == permissions.PrepareGarbageCollectionReferencesAction
	if allowed {
		return &auth.AuthorizationResponse{Allowed: true}, nil
	}
	return &auth.AuthorizationResponse{Allowed: false, Error: auth.ErrInsufficientPermissions}, nil
}

func TestGCReferencesRequiresGlobalPermissionBeforeCatalogAccess(t *testing.T) {
	for _, name := range []string{"prepare", "status"} {
		t.Run(name, func(t *testing.T) {
			service := &targetOnlyGCAuth{}
			// Nil catalog and configuration prove authorization precedes target lookup.
			controller := &api.Controller{Auth: service}
			response := httptest.NewRecorder()
			request := bindingAuthorizationRequest(t)
			if name == "prepare" {
				controller.PrepareGarbageCollectionReferencesAsync(response, request, apigen.PrepareGarbageCollectionReferencesAsyncJSONRequestBody{}, "owner")
			} else {
				controller.PrepareGarbageCollectionReferencesStatus(response, request, "owner", apigen.PrepareGarbageCollectionReferencesStatusParams{Id: "GCRmissing"})
			}
			require.Equal(t, http.StatusUnauthorized, response.Code)
			require.Len(t, service.requests, 1)
			require.Equal(t, permissions.Node{Permission: permissions.Permission{
				Action: permissions.PrepareGarbageCollectionReferencesAction, Resource: "*",
			}}, service.requests[0].RequiredPermissions)
		})
	}
}
