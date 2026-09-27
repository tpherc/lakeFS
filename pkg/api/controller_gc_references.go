package api

import (
	"net/http"
	"time"

	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/permissions"
)

const defaultGCMinimumAge = 24 * time.Hour

func (c *Controller) PrepareGarbageCollectionReferencesAsync(w http.ResponseWriter, r *http.Request, body apigen.PrepareGarbageCollectionReferencesAsyncJSONRequestBody, repository string) {
	if !c.authorize(w, r, permissions.Node{Permission: permissions.Permission{
		Action: permissions.PrepareGarbageCollectionReferencesAction, Resource: "*",
	}}) {
		return
	}
	minimumAge := int64(defaultGCMinimumAge / time.Second)
	if body.MinimumAgeSeconds != nil {
		minimumAge = *body.MinimumAgeSeconds
	}
	if minimumAge <= 0 || minimumAge > int64(time.Duration(1<<63-1)/time.Second) {
		writeError(w, r, http.StatusBadRequest, "minimum_age_seconds must be positive and fit a duration")
		return
	}
	ctx := r.Context()
	c.LogAction(ctx, "prepare_garbage_collection_references_async", r, repository, "", "")
	taskID, err := c.Catalog.PrepareGarbageCollectionReferences(ctx, repository, minimumAge)
	if c.handleAPIError(ctx, w, r, err) {
		return
	}
	writeResponse(w, r, http.StatusAccepted, apigen.TaskCreation{Id: taskID})
}

func (c *Controller) PrepareGarbageCollectionReferencesStatus(w http.ResponseWriter, r *http.Request, repository string, params apigen.PrepareGarbageCollectionReferencesStatusParams) {
	if !c.authorize(w, r, permissions.Node{Permission: permissions.Permission{
		Action: permissions.PrepareGarbageCollectionReferencesAction, Resource: "*",
	}}) {
		return
	}
	status, err := c.Catalog.GetGarbageCollectionReferencesStatus(r.Context(), repository, params.Id)
	if c.handleAPIError(r.Context(), w, r, err) {
		return
	}
	response := apigen.PrepareGarbageCollectionReferencesStatus{
		TaskId: status.Task.Id, Completed: status.Task.Done,
		Progress: status.Task.Progress, UpdateTime: status.Task.UpdatedAt.AsTime(),
	}
	if status.Task.ErrorMsg != "" {
		response.Error = &apigen.Error{Message: status.Task.ErrorMsg}
	}
	if status.Result != nil {
		response.Result = &apigen.GarbageCollectionReferencesResult{
			ManifestLocation: status.Result.ManifestLocation,
			ManifestSha256:   status.Result.ManifestSHA256,
			ExpiresAt:        status.Result.ExpiresAt,
		}
	}
	writeResponse(w, r, http.StatusOK, response)
}
