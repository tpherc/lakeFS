package api

import (
	"net/http"

	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/permissions"
)

// objectReadPermission uses stored metadata from the entry snapshot being read.
// A missing entry supplies no metadata, so conditioned allows do not match it.
func objectReadPermission(repository, path string, entry *catalog.DBEntry) permissions.Node {
	permission := permissions.Permission{Action: permissions.ReadObjectAction, Resource: permissions.ObjectArn(repository, path)}
	if entry != nil {
		permission.ObjectMetadata = entry.Metadata
	}
	return permissions.Node{Permission: permission}
}

// prepareObjectAuthorization rejects impossible action/path grants before object lookups.
// A possible grant still requires full authorization with the loaded metadata.
func (c *Controller) prepareObjectAuthorization(w http.ResponseWriter, r *http.Request, perms permissions.Node, respond func(http.ResponseWriter, *http.Request, int, any)) (*auth.PreparedAuthorization, bool) {
	user, err := auth.GetUser(r.Context())
	if err != nil {
		respond(w, r, http.StatusUnauthorized, ErrAuthenticatingRequest)
		return nil, false
	}
	prepared, err := auth.PrepareAuthorization(r.Context(), c.Auth, user.Username)
	if err != nil {
		respond(w, r, http.StatusInternalServerError, err)
		return nil, false
	}
	if !prepared.CanAuthorize(perms) {
		respond(w, r, http.StatusUnauthorized, auth.ErrInsufficientPermissions)
		return nil, false
	}
	return prepared, true
}
