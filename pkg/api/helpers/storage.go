package helpers

import (
	"context"
	"fmt"

	"github.com/go-openapi/swag"
	"github.com/treeverse/lakefs/pkg/api/apigen"
)

// ObjectSupportsPresign checks a saved source binding. Legacy entries inherit
// the caller's repository-level choice; unavailable sources use proxied reads.
func ObjectSupportsPresign(ctx context.Context, client *apigen.ClientWithResponses, storageID string) (bool, error) {
	if storageID == "" {
		return true, nil
	}
	response, err := client.GetConfigWithResponse(ctx)
	if err != nil {
		return false, err
	}
	if response.JSON200 == nil {
		return false, fmt.Errorf("get storage capabilities: %w: %s", ErrRequestFailed, response.Status())
	}
	if response.JSON200.StorageConfigList != nil {
		for _, storage := range *response.JSON200.StorageConfigList {
			if swag.StringValue(storage.BlockstoreId) == storageID {
				return storage.PreSignSupport, nil
			}
		}
	}
	return false, nil
}
