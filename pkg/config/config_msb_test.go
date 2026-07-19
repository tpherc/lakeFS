package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

func buildConfigFromYAML(t *testing.T, body string) (config.Config, error) {
	t.Helper()
	return buildConfigFromYAMLType(t, "", body)
}

func buildConfigFromYAMLType(t *testing.T, cfgType, body string) (config.Config, error) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(body)))
	return config.BuildConfig(cfgType)
}

func TestBlockstoresCanonicalConfigResolvesStorageIDs(t *testing.T) {
	cfg, err := buildConfigFromYAML(t, `
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
      description: Primary storage
      type: mem
      backward_compatible: true
    - id: beta
      type: mem
`)
	require.NoError(t, err)

	storageConfig := cfg.StorageConfig()
	require.True(t, storageConfig.IsMultiStorage())
	require.Equal(t, []string{"alpha", "beta"}, storageConfig.GetStorageIDs())
	require.Equal(t, "signing-secret", storageConfig.SigningKey().SecureValue())
	require.Equal(t, block.BlockstoreTypeMem, storageConfig.GetStorageByID("alpha").BlockstoreType())
	require.Equal(t, "Primary storage", storageConfig.GetStorageByID("alpha").BlockstoreDescription())

	newID, err := storageConfig.ResolveNewRepositoryStorageID("")
	require.NoError(t, err)
	require.Equal(t, "alpha", newID)
	storedID, err := storageConfig.ResolveStoredRepositoryStorageID("")
	require.NoError(t, err)
	require.Equal(t, "alpha", storedID)
	explicitID, err := storageConfig.ResolveNewRepositoryStorageID("beta")
	require.NoError(t, err)
	require.Equal(t, "beta", explicitID)
}

func TestBlockstoresCanonicalOneStoreIsMultiStorage(t *testing.T) {
	cfg, err := buildConfigFromYAML(t, `
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
`)
	require.NoError(t, err)

	storageConfig := cfg.StorageConfig()
	require.True(t, storageConfig.IsMultiStorage())
	require.Equal(t, []string{"alpha"}, storageConfig.GetStorageIDs())
	_, err = storageConfig.ResolveNewRepositoryStorageID(config.SingleBlockstoreID)
	require.NoError(t, err)
}

func TestBlockstoresWithoutCompatibleStoreRequiresExplicitRepositoryID(t *testing.T) {
	cfg, err := buildConfigFromYAML(t, `
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
    - id: beta
      type: mem
`)
	require.NoError(t, err)

	storageConfig := cfg.StorageConfig()
	newID, err := storageConfig.ResolveNewRepositoryStorageID("beta")
	require.NoError(t, err)
	require.Equal(t, "beta", newID)

	_, err = storageConfig.ResolveNewRepositoryStorageID("")
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
	_, err = storageConfig.ResolveStoredRepositoryStorageID("")
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
}

func TestBlockstoresRejectsMultipleCompatibleStores(t *testing.T) {
	_, err := buildConfigFromYAML(t, `
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
      backward_compatible: true
`)
	require.ErrorIs(t, err, config.ErrBadConfiguration)
}

func TestBlockstoresRejectsDuplicateAndBadStorageIDs(t *testing.T) {
	tests := []struct {
		name  string
		idOne string
		idTwo string
	}{
		{name: "duplicate", idOne: "alpha", idTwo: "alpha"},
		{name: "empty", idOne: "", idTwo: "beta"},
		{name: "starts with hyphen", idOne: "-alpha", idTwo: "beta"},
		{name: "contains space", idOne: "bad id", idTwo: "beta"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstores:
  signing:
    secret_key: signing-secret
  stores:
    - id: `+tt.idOne+`
      type: mem
    - id: `+tt.idTwo+`
      type: mem
`)
			require.ErrorIs(t, err, config.ErrBadConfiguration)
		})
	}
}

func TestBlockstoresRejectsMissingSigningKey(t *testing.T) {
	_, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstores:
  stores:
    - id: alpha
      type: mem
`)
	require.ErrorIs(t, err, config.ErrMissingRequiredKeys)
}

func TestBlockstoresRejectsExplicitEmptyStores(t *testing.T) {
	_, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstores:
  signing:
    secret_key: signing-secret
  stores: []
`)
	require.ErrorIs(t, err, config.ErrMissingRequiredKeys)
}

func TestBlockstoresIgnoresSingleBlockstoreDefaultsForMixedMode(t *testing.T) {
	_, err := buildConfigFromYAMLType(t, config.UseLocalConfiguration, `
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
`)
	require.NoError(t, err)
}

func TestBlockstoresRejectsMixedSingleAndMultiMode(t *testing.T) {
	_, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstore:
  signing:
    secret_key: legacy-signing
  type: mem
blockstores:
  signing:
    secret_key: signing-secret
  stores:
    - id: alpha
      type: mem
`)
	require.ErrorIs(t, err, config.ErrBadConfiguration)
}

func TestBlockstoresRejectsMixedNestedSingleProviderField(t *testing.T) {
	_, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstore:
  s3:
    region: us-east-1
blockstores:
  signing:
    secret_key: signing-secret
  stores:
    - id: alpha
      type: mem
`)
	require.ErrorIs(t, err, config.ErrBadConfiguration)
}

func TestBlockstoresRejectsMixedNestedSingleProviderEnvironment(t *testing.T) {
	t.Setenv("LAKEFS_BLOCKSTORE_S3_REGION", "us-west-2")
	_, err := buildConfigFromYAML(t, `
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
`)
	require.ErrorIs(t, err, config.ErrBadConfiguration)
}

func TestBlockstoresRejectsMixedModeFromEnvironment(t *testing.T) {
	t.Setenv("LAKEFS_BLOCKSTORE_TYPE", "mem")
	_, err := buildConfigFromYAML(t, `
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
`)
	require.ErrorIs(t, err, config.ErrBadConfiguration)
}

func TestBlockstoresRejectsMixedModeFromFileAndEnvironment(t *testing.T) {
	t.Setenv("LAKEFS_BLOCKSTORES_SIGNING_SECRET_KEY", "signing-secret")
	_, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstore:
  signing:
    secret_key: legacy-signing
  type: mem
`)
	require.ErrorIs(t, err, config.ErrBadConfiguration)
}

func TestBlockstoreStoragesIsRejected(t *testing.T) {
	_, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstore:
  signing:
    secret_key: signing-secret
  type: mem
  storages:
    alpha:
      type: mem
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid keys")
}

func TestBlockstoresAppliesBackendDefaultsToCanonicalStores(t *testing.T) {
	cfg, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstores:
  signing:
    secret_key: signing-secret
  stores:
    - id: local-store
      type: local
    - id: s3-store
      type: s3
    - id: gs-store
      type: gs
    - id: azure-store
      type: azure
`)
	require.NoError(t, err)

	localStore := cfg.StorageConfig().GetStorageByID("local-store").(*config.BlockstoreStorage)
	require.NotNil(t, localStore.Local)
	require.Equal(t, config.DefaultBlockstoreLocalPath, localStore.Local.Path)
	_, err = localStore.BlockstoreLocalParams()
	require.NoError(t, err)

	s3Store := cfg.StorageConfig().GetStorageByID("s3-store").(*config.BlockstoreStorage)
	require.NotNil(t, s3Store.S3)
	require.Equal(t, config.DefaultBlockstoreS3Region, s3Store.S3.Region)
	require.Equal(t, config.DefaultBlockstoreS3MaxRetries, s3Store.S3.MaxRetries)
	require.Equal(t, config.DefaultBlockstoreS3DiscoverBucketRegion, s3Store.S3.DiscoverBucketRegion)
	require.Equal(t, config.DefaultBlockstoreS3PreSignedExpiry, s3Store.S3.PreSignedExpiry)
	require.Equal(t, config.DefaultBlockstoreS3DisablePreSignedUI, s3Store.S3.DisablePreSignedUI)
	_, err = s3Store.BlockstoreS3Params()
	require.NoError(t, err)

	gsStore := cfg.StorageConfig().GetStorageByID("gs-store").(*config.BlockstoreStorage)
	require.NotNil(t, gsStore.GS)
	require.Equal(t, config.DefaultBlockstoreGSS3Endpoint, gsStore.GS.S3Endpoint)
	require.Equal(t, config.DefaultBlockstoreGSPreSignedExpiry, gsStore.GS.PreSignedExpiry)
	require.Equal(t, config.DefaultBlockstoreGSDisablePreSignedUI, gsStore.GS.DisablePreSignedUI)
	_, err = gsStore.BlockstoreGSParams()
	require.NoError(t, err)

	azureStore := cfg.StorageConfig().GetStorageByID("azure-store").(*config.BlockstoreStorage)
	require.NotNil(t, azureStore.Azure)
	require.Equal(t, config.DefaultBlockstoreAzureTryTimeout, azureStore.Azure.TryTimeout)
	require.Equal(t, config.DefaultBlockstoreAzurePreSignedExpiry, azureStore.Azure.PreSignedExpiry)
	require.Equal(t, config.DefaultBlockstoreAzureDisablePreSignedUI, azureStore.Azure.DisablePreSignedUI)
	_, err = azureStore.BlockstoreAzureParams()
	require.NoError(t, err)
}

func TestBlockstoresPreservesExplicitZeroAndFalseBackendValues(t *testing.T) {
	cfg, err := buildConfigFromYAML(t, `
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
      type: s3
      s3:
        max_retries: 0
        discover_bucket_region: false
        pre_signed_expiry: 0s
        disable_pre_signed_ui: false
`)
	require.NoError(t, err)

	storage := cfg.StorageConfig().GetStorageByID("alpha").(*config.BlockstoreStorage)
	require.NotNil(t, storage.S3)
	require.Equal(t, 0, storage.S3.MaxRetries)
	require.False(t, storage.S3.DiscoverBucketRegion)
	require.Equal(t, time.Duration(0), storage.S3.PreSignedExpiry)
	require.False(t, storage.S3.DisablePreSignedUI)
	require.Equal(t, config.DefaultBlockstoreS3Region, storage.S3.Region)
}

func TestValidateBlockstoreReturnsErrorForNilSelectedBackendConfig(t *testing.T) {
	blockstoreConfig := &config.Blockstore{}
	blockstoreConfig.Signing.SecretKey = "signing-secret"
	blockstoreConfig.Type = block.BlockstoreTypeS3

	err := config.ValidateBlockstore(blockstoreConfig)
	require.ErrorIs(t, err, config.ErrMissingRequiredKeys)
	require.Contains(t, err.Error(), "blockstore.s3")
}

func TestSingleBlockstoreRejectsPersistedStorageID(t *testing.T) {
	cfg, err := buildConfigFromYAML(t, `
database:
  type: local
auth:
  encrypt:
    secret_key: auth-secret
blockstore:
  signing:
    secret_key: signing-secret
  type: mem
`)
	require.NoError(t, err)

	storageConfig := cfg.StorageConfig()
	require.False(t, storageConfig.IsMultiStorage())
	id, err := storageConfig.ResolveNewRepositoryStorageID("")
	require.NoError(t, err)
	require.Equal(t, config.SingleBlockstoreID, id)
	_, err = storageConfig.ResolveStoredRepositoryStorageID("alpha")
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
}
