package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

var storageIDRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

type storageConfigSource struct {
	blockstore  bool
	blockstores bool
}

func detectStorageConfigSource() storageConfigSource {
	return storageConfigSource{
		blockstore:  configKeyInFileOrEnv("blockstore") || configKeyInFileOrEnv("blockstore.type") || configKeyInFileOrEnv("blockstore.storages"),
		blockstores: configKeyInFileOrEnv("blockstores") || explicitBlockstoresValue(),
	}
}

func configKeyInFileOrEnv(key string) bool {
	if viper.InConfig(key) {
		return true
	}
	envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	if _, ok := os.LookupEnv(envKey); ok {
		return true
	}
	if _, ok := os.LookupEnv("LAKEFS_" + envKey); ok {
		return true
	}
	return false
}

func explicitBlockstoresValue() bool {
	if configKeyInFileOrEnv("blockstores.stores") || configKeyInFileOrEnv("blockstores.signing.secret_key") {
		return true
	}
	if viper.Get("blockstores.stores") != nil {
		return true
	}
	return viper.GetString("blockstores.signing.secret_key") != ""
}

func validateStorageEntry(prefix string, cfg *BlockstoreConfig) error {
	if cfg == nil || cfg.Type == "" {
		return fmt.Errorf("'%s.type': %w", prefix, ErrMissingRequiredKeys)
	}
	return nil
}

// ResolveBlockstoreConfig normalizes the configured storage surface into the
// runtime storage registry. The documented MSB surface is blockstores.stores[];
// blockstore.storages intentionally has no config struct field and is rejected
// by exact unmarshalling. The legacy blockstore and canonical blockstores
// sections are mutually exclusive modes; explicit presence of both is a
// configuration error, with no precedence, merging, or implicit conversion.
func ResolveBlockstoreConfig(single *Blockstore, multi *Blockstores, source storageConfigSource) (*Blockstore, error) {
	if source.blockstore && source.blockstores {
		return nil, fmt.Errorf("'blockstores': %w", ErrBadConfiguration)
	}
	if source.blockstores {
		return resolveCanonicalBlockstores(multi)
	}

	resolved := &Blockstore{}
	if single != nil {
		*resolved = *single
	}
	return resolved, nil
}

func resolveCanonicalBlockstores(canonical *Blockstores) (*Blockstore, error) {
	if canonical == nil || len(canonical.Stores) == 0 {
		return nil, fmt.Errorf("'blockstores.stores': %w", ErrMissingRequiredKeys)
	}
	resolved := &Blockstore{
		storages:   make(map[string]*BlockstoreStorage, len(canonical.Stores)),
		storageIDs: make([]string, 0, len(canonical.Stores)),
	}
	resolved.Signing.SecretKey = canonical.Signing.SecretKey
	if resolved.Signing.SecretKey == "" {
		return nil, fmt.Errorf("'blockstores.signing.secret_key': %w", ErrMissingRequiredKeys)
	}

	compatibleCount := 0
	for i, store := range canonical.Stores {
		prefix := fmt.Sprintf("blockstores.stores[%d]", i)
		if store == nil {
			return nil, fmt.Errorf("'%s': %w", prefix, ErrBadConfiguration)
		}
		if store.ID == "" || !storageIDRegexp.MatchString(store.ID) {
			return nil, fmt.Errorf("'%s.id': %w", prefix, ErrBadConfiguration)
		}
		if _, exists := resolved.storages[store.ID]; exists {
			return nil, fmt.Errorf("'%s.id': %w", prefix, ErrBadConfiguration)
		}
		if err := validateStorageEntry(prefix, &store.BlockstoreConfig); err != nil {
			return nil, err
		}
		storage := &BlockstoreStorage{
			BlockstoreConfig:   store.BlockstoreConfig,
			Description:        store.Description,
			BackwardCompatible: store.BackwardCompatible,
			storageID:          store.ID,
		}
		resolved.storages[store.ID] = storage
		resolved.storageIDs = append(resolved.storageIDs, store.ID)
		if store.BackwardCompatible {
			compatibleCount++
			resolved.compatibleStorageID = store.ID
		}
	}
	if compatibleCount > 1 {
		return nil, fmt.Errorf("'blockstores.stores.backward_compatible': %w", ErrBadConfiguration)
	}
	return resolved, nil
}

func (b *Blockstore) IsMultiStorage() bool {
	return len(b.storages) > 0
}

func (b *Blockstore) ResolveNewRepositoryStorageID(storageID string) (string, error) {
	if !b.IsMultiStorage() {
		if storageID != SingleBlockstoreID {
			return "", fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
		}
		return SingleBlockstoreID, nil
	}
	if storageID == SingleBlockstoreID {
		if b.compatibleStorageID == "" {
			return "", fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
		}
		return b.compatibleStorageID, nil
	}
	if b.GetStorageByID(storageID) == nil {
		return "", fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
	}
	return storageID, nil
}

func (b *Blockstore) ResolveStoredRepositoryStorageID(storageID string) (string, error) {
	if !b.IsMultiStorage() {
		if storageID != SingleBlockstoreID {
			return "", fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
		}
		return SingleBlockstoreID, nil
	}
	if storageID == SingleBlockstoreID {
		if b.compatibleStorageID == "" {
			return "", fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
		}
		return b.compatibleStorageID, nil
	}
	if b.GetStorageByID(storageID) == nil {
		return "", fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
	}
	return storageID, nil
}

func (b *Blockstore) ValidateObjectStorageID(storageID string) error {
	if !b.IsMultiStorage() {
		if storageID != SingleBlockstoreID {
			return fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
		}
		return nil
	}
	if storageID == SingleBlockstoreID {
		return fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
	}
	if b.GetStorageByID(storageID) == nil {
		return fmt.Errorf("storage id %q: %w", storageID, ErrNoStorageConfig)
	}
	return nil
}
