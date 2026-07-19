package block

import (
	"context"
	"fmt"
)

type storageMetadataProvider interface {
	BlockstoreMetadataForStorage(ctx context.Context, storageID string) (*BlockstoreMetadata, error)
}

func ValidateInterRegionStorage(ctx context.Context, adapter Adapter, storageID, storageNamespace string) error {
	blockstoreMetadata, err := blockstoreMetadata(ctx, adapter, storageID)
	if err != nil {
		return err
	}
	if blockstoreMetadata.Region == nil {
		// region detection not supported for the server's blockstore, skip validation
		return nil
	}

	bucketRegion, err := adapter.GetRegion(ctx, storageID, storageNamespace)
	if err != nil {
		return fmt.Errorf("failed to get region of storage namespace %s: %w", storageNamespace, ErrInvalidNamespace)
	}

	blockstoreRegion := *blockstoreMetadata.Region
	if blockstoreRegion != bucketRegion {
		return fmt.Errorf(`%w: namespace region ("%s") does not match block region ("%s")`, ErrInvalidNamespace, bucketRegion, blockstoreRegion)
	}

	return nil
}

func blockstoreMetadata(ctx context.Context, adapter Adapter, storageID string) (*BlockstoreMetadata, error) {
	if storageID != "" {
		if provider, ok := adapter.(storageMetadataProvider); ok {
			return provider.BlockstoreMetadataForStorage(ctx, storageID)
		}
	}
	return adapter.BlockstoreMetadata(ctx)
}
