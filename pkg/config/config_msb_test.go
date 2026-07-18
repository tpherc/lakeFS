package config_test

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

func buildConfigFromYAML(t *testing.T, body string) (config.Config, error) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(body)))
	return config.BuildConfig("")
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
