package multi_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/block/multi"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/testutil"
)

type recordingAdapter struct {
	*testutil.MockAdapter
	putObjects       []block.ObjectPointer
	copyObjects      [][2]block.ObjectPointer
	uploadCopies     [][2]block.ObjectPointer
	rangeCopies      [][2]block.ObjectPointer
	walkerIDs        []string
	infoIDs          []string
	resolveIDs       []string
	regionIDs        []string
	runtimeStats     map[string]string
	metadata         block.BlockstoreMetadata
	namespaceInfoTyp string
}

func newRecordingAdapter(region string, productionSafe bool, stats map[string]string) *recordingAdapter {
	return &recordingAdapter{
		MockAdapter:      testutil.NewMockAdapter(),
		runtimeStats:     stats,
		metadata:         block.BlockstoreMetadata{IsProductionSafe: productionSafe, Region: stringPtr(region)},
		namespaceInfoTyp: block.BlockstoreTypeMem,
	}
}

func (a *recordingAdapter) Put(_ context.Context, obj block.ObjectPointer, _ int64, _ io.Reader, _ block.PutOpts) (*block.PutResponse, error) {
	a.putObjects = append(a.putObjects, obj)
	return &block.PutResponse{}, nil
}

func (a *recordingAdapter) Copy(_ context.Context, sourceObj, destinationObj block.ObjectPointer) error {
	a.copyObjects = append(a.copyObjects, [2]block.ObjectPointer{sourceObj, destinationObj})
	return nil
}

func (a *recordingAdapter) UploadCopyPart(_ context.Context, sourceObj, destinationObj block.ObjectPointer, _ string, _ int) (*block.UploadPartResponse, error) {
	a.uploadCopies = append(a.uploadCopies, [2]block.ObjectPointer{sourceObj, destinationObj})
	return &block.UploadPartResponse{}, nil
}

func (a *recordingAdapter) UploadCopyPartRange(_ context.Context, sourceObj, destinationObj block.ObjectPointer, _ string, _ int, _, _ int64) (*block.UploadPartResponse, error) {
	a.rangeCopies = append(a.rangeCopies, [2]block.ObjectPointer{sourceObj, destinationObj})
	return &block.UploadPartResponse{}, nil
}

func (a *recordingAdapter) GetWalker(storageID string, _ block.WalkerOptions) (block.Walker, error) {
	a.walkerIDs = append(a.walkerIDs, storageID)
	return nil, nil
}

func (a *recordingAdapter) GetStorageNamespaceInfo(storageID string) *block.StorageNamespaceInfo {
	a.infoIDs = append(a.infoIDs, storageID)
	info := block.DefaultStorageNamespaceInfo(a.namespaceInfoTyp)
	return &info
}

func (a *recordingAdapter) ResolveNamespace(storageID, storageNamespace, key string, identifierType block.IdentifierType) (block.QualifiedKey, error) {
	a.resolveIDs = append(a.resolveIDs, storageID)
	return block.DefaultResolveNamespace(storageNamespace, key, identifierType)
}

func (a *recordingAdapter) GetRegion(_ context.Context, storageID, _ string) (string, error) {
	a.regionIDs = append(a.regionIDs, storageID)
	return "region-" + storageID, nil
}

func (a *recordingAdapter) RuntimeStats() map[string]string {
	return a.runtimeStats
}

func (a *recordingAdapter) BlockstoreMetadata(_ context.Context) (*block.BlockstoreMetadata, error) {
	return &a.metadata, nil
}

func TestAdapterRoutesConcreteObjectStorageID(t *testing.T) {
	router, alpha, beta := buildRouter(t)

	_, err := router.Put(t.Context(), block.ObjectPointer{
		StorageID:        "beta",
		StorageNamespace: "mem://beta",
		Identifier:       "key",
		IdentifierType:   block.IdentifierTypeRelative,
	}, 0, strings.NewReader("data"), block.PutOpts{})
	require.NoError(t, err)
	require.Empty(t, alpha.putObjects)
	require.Len(t, beta.putObjects, 1)
	require.Equal(t, "beta", beta.putObjects[0].StorageID)
}

func TestAdapterRejectsEmptyObjectStorageID(t *testing.T) {
	router, alpha, beta := buildRouter(t)

	_, err := router.Put(t.Context(), block.ObjectPointer{
		StorageID:        config.SingleBlockstoreID,
		StorageNamespace: "mem://alpha",
		Identifier:       "key",
		IdentifierType:   block.IdentifierTypeRelative,
	}, 0, strings.NewReader("data"), block.PutOpts{})
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
	require.Empty(t, alpha.putObjects)
	require.Empty(t, beta.putObjects)
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

	_, err = router.Put(t.Context(), block.ObjectPointer{
		StorageID:        config.SingleBlockstoreID,
		StorageNamespace: "mem://alpha",
		Identifier:       "key",
		IdentifierType:   block.IdentifierTypeRelative,
	}, 0, strings.NewReader("data"), block.PutOpts{})
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
	require.Empty(t, alpha.putObjects)
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

func TestAdapterRejectsCrossStorageCopyBeforeCallingChildren(t *testing.T) {
	router, alpha, beta := buildRouter(t)
	source := block.ObjectPointer{StorageID: "alpha", StorageNamespace: "mem://alpha", Identifier: "src", IdentifierType: block.IdentifierTypeRelative}
	destination := block.ObjectPointer{StorageID: "beta", StorageNamespace: "mem://beta", Identifier: "dst", IdentifierType: block.IdentifierTypeRelative}

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

func stringPtr(v string) *string {
	return &v
}
