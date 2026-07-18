package multi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

// Adapter routes block operations to one of several concrete storage adapters.
type Adapter struct {
	adapters map[string]block.Adapter
}

// BuildMultiStorageAdapter returns the single concrete adapter in legacy
// single-backend mode, or a routing adapter for canonical multi-backend mode.
func BuildMultiStorageAdapter(storageConfig config.StorageConfig, builtAdapters map[string]block.Adapter) (block.Adapter, error) {
	storageIDs := storageConfig.GetStorageIDs()
	for _, storageID := range storageIDs {
		if _, ok := builtAdapters[storageID]; !ok {
			return nil, fmt.Errorf("storage id %q: %w", storageID, config.ErrBadConfiguration)
		}
	}
	for storageID := range builtAdapters {
		if !containsStorageID(storageIDs, storageID) {
			return nil, fmt.Errorf("storage id %q: %w", storageID, config.ErrBadConfiguration)
		}
	}
	if len(storageIDs) == 1 && !storageConfig.IsMultiStorage() {
		return builtAdapters[storageIDs[0]], nil
	}

	return &Adapter{
		adapters: builtAdapters,
	}, nil
}

func containsStorageID(storageIDs []string, storageID string) bool {
	for _, id := range storageIDs {
		if id == storageID {
			return true
		}
	}
	return false
}

func (a *Adapter) resolveStorageID(storageID string) (string, error) {
	if storageID == config.SingleBlockstoreID {
		return "", fmt.Errorf("storage id %q: %w", storageID, config.ErrNoStorageConfig)
	}
	if _, ok := a.adapters[storageID]; !ok {
		return "", fmt.Errorf("storage id %q: %w", storageID, config.ErrNoStorageConfig)
	}
	return storageID, nil
}

// ResolveAdapter resolves a concrete configured storage ID to its adapter.
func (a *Adapter) ResolveAdapter(storageID string) (block.Adapter, error) {
	resolvedStorageID, err := a.resolveStorageID(storageID)
	if err != nil {
		return nil, err
	}
	return a.adapters[resolvedStorageID], nil
}

func (a *Adapter) adapterForObject(obj block.ObjectPointer) (block.ObjectPointer, block.Adapter, error) {
	resolvedStorageID, err := a.resolveStorageID(obj.StorageID)
	if err != nil {
		return block.ObjectPointer{}, nil, err
	}
	obj.StorageID = resolvedStorageID
	return obj, a.adapters[resolvedStorageID], nil
}

func (a *Adapter) normalizeCopyTargets(sourceObj, destinationObj block.ObjectPointer) (block.ObjectPointer, block.ObjectPointer, block.Adapter, error) {
	resolvedSourceID, err := a.resolveStorageID(sourceObj.StorageID)
	if err != nil {
		return block.ObjectPointer{}, block.ObjectPointer{}, nil, err
	}
	resolvedDestinationID, err := a.resolveStorageID(destinationObj.StorageID)
	if err != nil {
		return block.ObjectPointer{}, block.ObjectPointer{}, nil, err
	}
	if resolvedSourceID != resolvedDestinationID {
		return block.ObjectPointer{}, block.ObjectPointer{}, nil, fmt.Errorf(
			"cross-storage copy between %q and %q: %w",
			sourceObj.StorageID,
			destinationObj.StorageID,
			block.ErrOperationNotSupported,
		)
	}
	sourceObj.StorageID = resolvedSourceID
	destinationObj.StorageID = resolvedDestinationID
	return sourceObj, destinationObj, a.adapters[resolvedSourceID], nil
}

func (a *Adapter) Put(ctx context.Context, obj block.ObjectPointer, sizeBytes int64, reader io.Reader, opts block.PutOpts) (*block.PutResponse, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.Put(ctx, obj, sizeBytes, reader, opts)
}

func (a *Adapter) Get(ctx context.Context, obj block.ObjectPointer) (io.ReadCloser, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.Get(ctx, obj)
}

func (a *Adapter) GetWalker(storageID string, opts block.WalkerOptions) (block.Walker, error) {
	adapter, err := a.ResolveAdapter(storageID)
	if err != nil {
		return nil, err
	}
	return adapter.GetWalker(storageID, opts)
}

func (a *Adapter) GetPreSignedURL(ctx context.Context, obj block.ObjectPointer, mode block.PreSignMode, filename string) (string, time.Time, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return "", time.Time{}, err
	}
	return adapter.GetPreSignedURL(ctx, obj, mode, filename)
}

func (a *Adapter) GetPresignUploadPartURL(ctx context.Context, obj block.ObjectPointer, uploadID string, partNumber int) (string, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return "", err
	}
	return adapter.GetPresignUploadPartURL(ctx, obj, uploadID, partNumber)
}

func (a *Adapter) Exists(ctx context.Context, obj block.ObjectPointer) (bool, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return false, err
	}
	return adapter.Exists(ctx, obj)
}

func (a *Adapter) GetRange(ctx context.Context, obj block.ObjectPointer, startPosition int64, endPosition int64) (io.ReadCloser, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.GetRange(ctx, obj, startPosition, endPosition)
}

func (a *Adapter) GetProperties(ctx context.Context, obj block.ObjectPointer) (block.Properties, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return block.Properties{}, err
	}
	return adapter.GetProperties(ctx, obj)
}

func (a *Adapter) Copy(ctx context.Context, sourceObj, destinationObj block.ObjectPointer) error {
	sourceObj, destinationObj, adapter, err := a.normalizeCopyTargets(sourceObj, destinationObj)
	if err != nil {
		return err
	}
	return adapter.Copy(ctx, sourceObj, destinationObj)
}

func (a *Adapter) CreateMultiPartUpload(ctx context.Context, obj block.ObjectPointer, r *http.Request, opts block.CreateMultiPartUploadOpts) (*block.CreateMultiPartUploadResponse, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.CreateMultiPartUpload(ctx, obj, r, opts)
}

func (a *Adapter) UploadPart(ctx context.Context, obj block.ObjectPointer, sizeBytes int64, reader io.Reader, uploadID string, partNumber int) (*block.UploadPartResponse, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.UploadPart(ctx, obj, sizeBytes, reader, uploadID, partNumber)
}

func (a *Adapter) UploadCopyPart(ctx context.Context, sourceObj, destinationObj block.ObjectPointer, uploadID string, partNumber int) (*block.UploadPartResponse, error) {
	sourceObj, destinationObj, adapter, err := a.normalizeCopyTargets(sourceObj, destinationObj)
	if err != nil {
		return nil, err
	}
	return adapter.UploadCopyPart(ctx, sourceObj, destinationObj, uploadID, partNumber)
}

func (a *Adapter) UploadCopyPartRange(ctx context.Context, sourceObj, destinationObj block.ObjectPointer, uploadID string, partNumber int, startPosition, endPosition int64) (*block.UploadPartResponse, error) {
	sourceObj, destinationObj, adapter, err := a.normalizeCopyTargets(sourceObj, destinationObj)
	if err != nil {
		return nil, err
	}
	return adapter.UploadCopyPartRange(ctx, sourceObj, destinationObj, uploadID, partNumber, startPosition, endPosition)
}

func (a *Adapter) ListParts(ctx context.Context, obj block.ObjectPointer, uploadID string, opts block.ListPartsOpts) (*block.ListPartsResponse, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.ListParts(ctx, obj, uploadID, opts)
}

func (a *Adapter) ListMultipartUploads(ctx context.Context, obj block.ObjectPointer, opts block.ListMultipartUploadsOpts) (*block.ListMultipartUploadsResponse, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.ListMultipartUploads(ctx, obj, opts)
}

func (a *Adapter) AbortMultiPartUpload(ctx context.Context, obj block.ObjectPointer, uploadID string) error {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return err
	}
	return adapter.AbortMultiPartUpload(ctx, obj, uploadID)
}

func (a *Adapter) CompleteMultiPartUpload(ctx context.Context, obj block.ObjectPointer, uploadID string, multipartList *block.MultipartUploadCompletion) (*block.CompleteMultiPartUploadResponse, error) {
	obj, adapter, err := a.adapterForObject(obj)
	if err != nil {
		return nil, err
	}
	return adapter.CompleteMultiPartUpload(ctx, obj, uploadID, multipartList)
}

func (a *Adapter) BlockstoreType() string {
	return "multi"
}

// BlockstoreMetadataForStorage returns adapter metadata for a specific storage
// ID.
func (a *Adapter) BlockstoreMetadataForStorage(ctx context.Context, storageID string) (*block.BlockstoreMetadata, error) {
	adapter, err := a.ResolveAdapter(storageID)
	if err != nil {
		return nil, err
	}
	return adapter.BlockstoreMetadata(ctx)
}

func (a *Adapter) BlockstoreMetadata(ctx context.Context) (*block.BlockstoreMetadata, error) {
	storageIDs := make([]string, 0, len(a.adapters))
	for storageID := range a.adapters {
		storageIDs = append(storageIDs, storageID)
	}
	sort.Strings(storageIDs)

	metadata := &block.BlockstoreMetadata{IsProductionSafe: true}
	for i, storageID := range storageIDs {
		current, err := a.adapters[storageID].BlockstoreMetadata(ctx)
		if err != nil {
			return nil, err
		}
		metadata.IsProductionSafe = metadata.IsProductionSafe && current.IsProductionSafe
		switch {
		case i == 0 && current.Region != nil:
			region := *current.Region
			metadata.Region = &region
		case metadata.Region == nil || current.Region == nil || *metadata.Region != *current.Region:
			metadata.Region = nil
		}
	}
	return metadata, nil
}

func (a *Adapter) GetStorageNamespaceInfo(storageID string) *block.StorageNamespaceInfo {
	adapter, err := a.ResolveAdapter(storageID)
	if err != nil {
		return nil
	}
	return adapter.GetStorageNamespaceInfo(storageID)
}

func (a *Adapter) ResolveNamespace(storageID, storageNamespace, key string, identifierType block.IdentifierType) (block.QualifiedKey, error) {
	adapter, err := a.ResolveAdapter(storageID)
	if err != nil {
		return nil, err
	}
	return adapter.ResolveNamespace(storageID, storageNamespace, key, identifierType)
}

func (a *Adapter) GetRegion(ctx context.Context, storageID, storageNamespace string) (string, error) {
	adapter, err := a.ResolveAdapter(storageID)
	if err != nil {
		return "", err
	}
	return adapter.GetRegion(ctx, storageID, storageNamespace)
}

func (a *Adapter) RuntimeStats() map[string]string {
	stats := make(map[string]string)
	for storageID, adapter := range a.adapters {
		for key, value := range adapter.RuntimeStats() {
			stats[storageID+"."+key] = value
		}
	}
	return stats
}
