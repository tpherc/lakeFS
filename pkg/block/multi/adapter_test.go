package multi_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/block/multi"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/testutil"
)

type recordingAdapter struct {
	*testutil.MockAdapter
	objectCalls     map[string][]block.ObjectPointer
	copyObjects     [][2]block.ObjectPointer
	uploadCopies    [][2]block.ObjectPointer
	rangeCopies     [][2]block.ObjectPointer
	walkerIDs       []string
	infoIDs         []string
	resolveIDs      []string
	regionIDs       []string
	regionResult    string
	runtimeStats    map[string]string
	metadata        block.BlockstoreMetadata
	namespaceInfoTy string
}

func newRecordingAdapter(region string, productionSafe bool, stats map[string]string) *recordingAdapter {
	return &recordingAdapter{
		MockAdapter:     testutil.NewMockAdapter(),
		objectCalls:     make(map[string][]block.ObjectPointer),
		regionResult:    region,
		runtimeStats:    stats,
		metadata:        block.BlockstoreMetadata{IsProductionSafe: productionSafe, Region: stringPtr(region)},
		namespaceInfoTy: block.BlockstoreTypeMem,
	}
}

func (a *recordingAdapter) recordObject(method string, obj block.ObjectPointer) {
	a.objectCalls[method] = append(a.objectCalls[method], obj)
}

func (a *recordingAdapter) Put(_ context.Context, obj block.ObjectPointer, _ int64, _ io.Reader, _ block.PutOpts) (*block.PutResponse, error) {
	a.recordObject("Put", obj)
	return &block.PutResponse{}, nil
}

func (a *recordingAdapter) Get(_ context.Context, obj block.ObjectPointer) (io.ReadCloser, error) {
	a.recordObject("Get", obj)
	return io.NopCloser(strings.NewReader("")), nil
}

func (a *recordingAdapter) GetPreSignedURL(_ context.Context, obj block.ObjectPointer, _ block.PreSignMode, _ string) (string, time.Time, error) {
	a.recordObject("GetPreSignedURL", obj)
	return "https://example.test/object", time.Time{}, nil
}

func (a *recordingAdapter) GetPresignUploadPartURL(_ context.Context, obj block.ObjectPointer, _ string, _ int) (string, error) {
	a.recordObject("GetPresignUploadPartURL", obj)
	return "https://example.test/object/part", nil
}

func (a *recordingAdapter) Exists(_ context.Context, obj block.ObjectPointer) (bool, error) {
	a.recordObject("Exists", obj)
	return true, nil
}

func (a *recordingAdapter) GetRange(_ context.Context, obj block.ObjectPointer, _, _ int64) (io.ReadCloser, error) {
	a.recordObject("GetRange", obj)
	return io.NopCloser(strings.NewReader("")), nil
}

func (a *recordingAdapter) GetProperties(_ context.Context, obj block.ObjectPointer) (block.Properties, error) {
	a.recordObject("GetProperties", obj)
	return block.Properties{}, nil
}

func (a *recordingAdapter) Copy(_ context.Context, sourceObj, destinationObj block.ObjectPointer) error {
	a.copyObjects = append(a.copyObjects, [2]block.ObjectPointer{sourceObj, destinationObj})
	return nil
}

func (a *recordingAdapter) CreateMultiPartUpload(_ context.Context, obj block.ObjectPointer, _ *http.Request, _ block.CreateMultiPartUploadOpts) (*block.CreateMultiPartUploadResponse, error) {
	a.recordObject("CreateMultiPartUpload", obj)
	return &block.CreateMultiPartUploadResponse{UploadID: "upload-id"}, nil
}

func (a *recordingAdapter) UploadPart(_ context.Context, obj block.ObjectPointer, _ int64, _ io.Reader, _ string, _ int) (*block.UploadPartResponse, error) {
	a.recordObject("UploadPart", obj)
	return &block.UploadPartResponse{ETag: "etag"}, nil
}

func (a *recordingAdapter) UploadCopyPart(_ context.Context, sourceObj, destinationObj block.ObjectPointer, _ string, _ int) (*block.UploadPartResponse, error) {
	a.uploadCopies = append(a.uploadCopies, [2]block.ObjectPointer{sourceObj, destinationObj})
	return &block.UploadPartResponse{ETag: "etag"}, nil
}

func (a *recordingAdapter) UploadCopyPartRange(_ context.Context, sourceObj, destinationObj block.ObjectPointer, _ string, _ int, _, _ int64) (*block.UploadPartResponse, error) {
	a.rangeCopies = append(a.rangeCopies, [2]block.ObjectPointer{sourceObj, destinationObj})
	return &block.UploadPartResponse{ETag: "etag"}, nil
}

func (a *recordingAdapter) ListParts(_ context.Context, obj block.ObjectPointer, _ string, _ block.ListPartsOpts) (*block.ListPartsResponse, error) {
	a.recordObject("ListParts", obj)
	return &block.ListPartsResponse{}, nil
}

func (a *recordingAdapter) ListMultipartUploads(_ context.Context, obj block.ObjectPointer, _ block.ListMultipartUploadsOpts) (*block.ListMultipartUploadsResponse, error) {
	a.recordObject("ListMultipartUploads", obj)
	return &block.ListMultipartUploadsResponse{}, nil
}

func (a *recordingAdapter) AbortMultiPartUpload(_ context.Context, obj block.ObjectPointer, _ string) error {
	a.recordObject("AbortMultiPartUpload", obj)
	return nil
}

func (a *recordingAdapter) CompleteMultiPartUpload(_ context.Context, obj block.ObjectPointer, _ string, _ *block.MultipartUploadCompletion) (*block.CompleteMultiPartUploadResponse, error) {
	a.recordObject("CompleteMultiPartUpload", obj)
	return &block.CompleteMultiPartUploadResponse{}, nil
}

func (a *recordingAdapter) GetWalker(storageID string, _ block.WalkerOptions) (block.Walker, error) {
	a.walkerIDs = append(a.walkerIDs, storageID)
	return nil, nil
}

func (a *recordingAdapter) GetStorageNamespaceInfo(storageID string) *block.StorageNamespaceInfo {
	a.infoIDs = append(a.infoIDs, storageID)
	info := block.DefaultStorageNamespaceInfo(a.namespaceInfoTy)
	return &info
}

func (a *recordingAdapter) ResolveNamespace(storageID, storageNamespace, key string, identifierType block.IdentifierType) (block.QualifiedKey, error) {
	a.resolveIDs = append(a.resolveIDs, storageID)
	return block.DefaultResolveNamespace(storageNamespace, key, identifierType)
}

func (a *recordingAdapter) GetRegion(_ context.Context, storageID, _ string) (string, error) {
	a.regionIDs = append(a.regionIDs, storageID)
	return a.regionResult, nil
}

func (a *recordingAdapter) RuntimeStats() map[string]string {
	return a.runtimeStats
}

func (a *recordingAdapter) BlockstoreMetadata(_ context.Context) (*block.BlockstoreMetadata, error) {
	return &a.metadata, nil
}

type objectMethod struct {
	name string
	call func(context.Context, block.Adapter, block.ObjectPointer) error
}

func objectMethods(t *testing.T) []objectMethod {
	t.Helper()
	return []objectMethod{
		{
			name: "Put",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.Put(ctx, obj, 4, strings.NewReader("data"), block.PutOpts{})
				return err
			},
		},
		{
			name: "Get",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				reader, err := adapter.Get(ctx, obj)
				if reader != nil {
					require.NoError(t, reader.Close())
				}
				return err
			},
		},
		{
			name: "GetPreSignedURL",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, _, err := adapter.GetPreSignedURL(ctx, obj, block.PreSignModeRead, "file.txt")
				return err
			},
		},
		{
			name: "GetPresignUploadPartURL",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.GetPresignUploadPartURL(ctx, obj, "upload-id", 1)
				return err
			},
		},
		{
			name: "Exists",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.Exists(ctx, obj)
				return err
			},
		},
		{
			name: "GetRange",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				reader, err := adapter.GetRange(ctx, obj, 0, 5)
				if reader != nil {
					require.NoError(t, reader.Close())
				}
				return err
			},
		},
		{
			name: "GetProperties",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.GetProperties(ctx, obj)
				return err
			},
		},
		{
			name: "CreateMultiPartUpload",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.CreateMultiPartUpload(ctx, obj, nil, block.CreateMultiPartUploadOpts{})
				return err
			},
		},
		{
			name: "UploadPart",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.UploadPart(ctx, obj, 4, strings.NewReader("part"), "upload-id", 1)
				return err
			},
		},
		{
			name: "ListParts",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.ListParts(ctx, obj, "upload-id", block.ListPartsOpts{})
				return err
			},
		},
		{
			name: "ListMultipartUploads",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.ListMultipartUploads(ctx, obj, block.ListMultipartUploadsOpts{})
				return err
			},
		},
		{
			name: "AbortMultiPartUpload",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				return adapter.AbortMultiPartUpload(ctx, obj, "upload-id")
			},
		},
		{
			name: "CompleteMultiPartUpload",
			call: func(ctx context.Context, adapter block.Adapter, obj block.ObjectPointer) error {
				_, err := adapter.CompleteMultiPartUpload(ctx, obj, "upload-id", &block.MultipartUploadCompletion{})
				return err
			},
		},
	}
}

func TestAdapterRoutesConcreteObjectStorageID(t *testing.T) {
	for _, method := range objectMethods(t) {
		t.Run(method.name, func(t *testing.T) {
			router, alpha, beta := buildRouter(t)
			obj := objectPointer("beta", "key")

			require.NoError(t, method.call(t.Context(), router, obj))
			require.Empty(t, alpha.objectCalls)
			require.Len(t, beta.objectCalls[method.name], 1)
			require.Equal(t, "beta", beta.objectCalls[method.name][0].StorageID)
		})
	}
}

func TestAdapterRejectsInvalidObjectStorageID(t *testing.T) {
	for _, storageID := range []string{config.SingleBlockstoreID, "gamma"} {
		for _, method := range objectMethods(t) {
			t.Run(method.name+"/"+storageID, func(t *testing.T) {
				router, alpha, beta := buildRouter(t)

				err := method.call(t.Context(), router, objectPointer(storageID, "key"))
				require.ErrorIs(t, err, config.ErrNoStorageConfig)
				require.Empty(t, alpha.objectCalls)
				require.Empty(t, beta.objectCalls)
			})
		}
	}
}

func TestBuildMultiStorageAdapterKeepsSingleStoreMSBStrict(t *testing.T) {
	cfg := buildSingleStoreMultiConfig(t)
	alpha := newRecordingAdapter("us-east-1", true, map[string]string{"ops": "1"})
	adapter, err := multi.BuildMultiStorageAdapter(cfg.StorageConfig(), map[string]block.Adapter{
		"alpha": alpha,
	})
	require.NoError(t, err)
	router, ok := adapter.(*multi.Adapter)
	require.True(t, ok)

	_, err = router.Put(t.Context(), objectPointer(config.SingleBlockstoreID, "key"), 0, strings.NewReader("data"), block.PutOpts{})
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
	require.Empty(t, alpha.objectCalls)

	_, err = router.Put(t.Context(), objectPointer("alpha", "key"), 0, strings.NewReader("data"), block.PutOpts{})
	require.NoError(t, err)
	require.Len(t, alpha.objectCalls["Put"], 1)
	require.Equal(t, "alpha", alpha.objectCalls["Put"][0].StorageID)
}

func TestAdapterRoutesExplicitStorageIDMethods(t *testing.T) {
	router, alpha, beta := buildRouter(t)

	_, err := router.GetWalker("beta", block.WalkerOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"beta"}, beta.walkerIDs)

	require.NotNil(t, router.GetStorageNamespaceInfo("alpha"))
	require.Equal(t, []string{"alpha"}, alpha.infoIDs)

	_, err = router.ResolveNamespace("beta", "mem://beta", "key", block.IdentifierTypeRelative)
	require.NoError(t, err)
	require.Equal(t, []string{"beta"}, beta.resolveIDs)

	_, err = router.GetRegion(t.Context(), "alpha", "mem://alpha")
	require.NoError(t, err)
	require.Equal(t, []string{"alpha"}, alpha.regionIDs)
}

func TestAdapterRoutesSameStorageCopy(t *testing.T) {
	testCases := []struct {
		name     string
		call     func(context.Context, block.Adapter, block.ObjectPointer, block.ObjectPointer) error
		recorded func(*recordingAdapter) [][2]block.ObjectPointer
	}{
		{
			name: "Copy",
			call: func(ctx context.Context, adapter block.Adapter, source, destination block.ObjectPointer) error {
				return adapter.Copy(ctx, source, destination)
			},
			recorded: func(adapter *recordingAdapter) [][2]block.ObjectPointer { return adapter.copyObjects },
		},
		{
			name: "UploadCopyPart",
			call: func(ctx context.Context, adapter block.Adapter, source, destination block.ObjectPointer) error {
				_, err := adapter.UploadCopyPart(ctx, source, destination, "upload-id", 1)
				return err
			},
			recorded: func(adapter *recordingAdapter) [][2]block.ObjectPointer { return adapter.uploadCopies },
		},
		{
			name: "UploadCopyPartRange",
			call: func(ctx context.Context, adapter block.Adapter, source, destination block.ObjectPointer) error {
				_, err := adapter.UploadCopyPartRange(ctx, source, destination, "upload-id", 1, 0, 10)
				return err
			},
			recorded: func(adapter *recordingAdapter) [][2]block.ObjectPointer { return adapter.rangeCopies },
		},
	}

	for _, storageID := range []string{"alpha", "beta"} {
		for _, tc := range testCases {
			t.Run(tc.name+"/"+storageID, func(t *testing.T) {
				router, alpha, beta := buildRouter(t)
				source := objectPointer(storageID, "src")
				destination := objectPointer(storageID, "dst")
				called := map[string]*recordingAdapter{"alpha": alpha, "beta": beta}[storageID]
				notCalled := map[string]*recordingAdapter{"alpha": beta, "beta": alpha}[storageID]

				require.NoError(t, tc.call(t.Context(), router, source, destination))
				require.Len(t, tc.recorded(called), 1)
				require.Equal(t, storageID, tc.recorded(called)[0][0].StorageID)
				require.Equal(t, storageID, tc.recorded(called)[0][1].StorageID)
				require.Empty(t, tc.recorded(notCalled))
			})
		}
	}
}

func TestAdapterRejectsCrossStorageCopyBeforeCallingChildren(t *testing.T) {
	router, alpha, beta := buildRouter(t)
	source := objectPointer("alpha", "src")
	destination := objectPointer("beta", "dst")

	err := router.Copy(t.Context(), source, destination)
	require.ErrorIs(t, err, block.ErrOperationNotSupported)
	_, err = router.UploadCopyPart(t.Context(), source, destination, "upload-id", 1)
	require.ErrorIs(t, err, block.ErrOperationNotSupported)
	_, err = router.UploadCopyPartRange(t.Context(), source, destination, "upload-id", 1, 0, 10)
	require.ErrorIs(t, err, block.ErrOperationNotSupported)

	require.Empty(t, alpha.copyObjects)
	require.Empty(t, beta.copyObjects)
	require.Empty(t, alpha.uploadCopies)
	require.Empty(t, beta.uploadCopies)
	require.Empty(t, alpha.rangeCopies)
	require.Empty(t, beta.rangeCopies)
}

func TestAdapterGlobalMetadataAndStatsAreDeterministic(t *testing.T) {
	router, _, _ := buildRouter(t)

	metadata, err := router.BlockstoreMetadata(t.Context())
	require.NoError(t, err)
	require.False(t, metadata.IsProductionSafe)
	require.Nil(t, metadata.Region)
	require.Equal(t, map[string]string{
		"alpha.ops": "1",
		"beta.ops":  "2",
	}, router.RuntimeStats())
}

func TestValidateInterRegionStorageUsesSelectedStorageMetadata(t *testing.T) {
	router, alpha, beta := buildRouter(t)
	beta.regionResult = "us-east-1"

	err := block.ValidateInterRegionStorage(t.Context(), router, "beta", "mem://beta")
	require.ErrorIs(t, err, block.ErrInvalidNamespace)
	require.Equal(t, []string{"beta"}, beta.regionIDs)
	require.Empty(t, alpha.regionIDs)
}

func buildRouter(t *testing.T) (*multi.Adapter, *recordingAdapter, *recordingAdapter) {
	t.Helper()
	cfg := buildMultiConfig(t)
	alpha := newRecordingAdapter("us-east-1", true, map[string]string{"ops": "1"})
	beta := newRecordingAdapter("us-west-2", false, map[string]string{"ops": "2"})
	adapter, err := multi.BuildMultiStorageAdapter(cfg.StorageConfig(), map[string]block.Adapter{
		"alpha": alpha,
		"beta":  beta,
	})
	require.NoError(t, err)
	router, ok := adapter.(*multi.Adapter)
	require.True(t, ok)
	return router, alpha, beta
}

func buildMultiConfig(t *testing.T) config.Config {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstores:
  signing:
    secret_key: signing-secret
  stores:
    - id: alpha
      type: mem
      backward_compatible: true
    - id: beta
      type: mem
`)))
	cfg, err := config.BuildConfig("")
	require.NoError(t, err)
	return cfg
}

func buildSingleStoreMultiConfig(t *testing.T) config.Config {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstores:
  signing:
    secret_key: signing-secret
  stores:
    - id: alpha
      type: mem
      backward_compatible: true
`)))
	cfg, err := config.BuildConfig("")
	require.NoError(t, err)
	return cfg
}

func objectPointer(storageID, identifier string) block.ObjectPointer {
	return block.ObjectPointer{
		StorageID:        storageID,
		StorageNamespace: "mem://" + storageID,
		Identifier:       identifier,
		IdentifierType:   block.IdentifierTypeRelative,
	}
}

func stringPtr(v string) *string {
	return &v
}
