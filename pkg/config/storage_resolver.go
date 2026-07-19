package config

import (
	"encoding/json"
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
		blockstore:  configTreeInFileOrEnv("blockstore") || configKeyInFileOrEnv("blockstore.type") || configKeyInFileOrEnv("blockstore.storages"),
		blockstores: configTreeInFileOrEnv("blockstores") || explicitBlockstoresValue(),
	}
}

func configTreeInFileOrEnv(key string) bool {
	return viper.InConfig(key) || envTreeExists(key)
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

func envTreeExists(key string) bool {
	envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	for _, item := range os.Environ() {
		envName, _, _ := strings.Cut(item, "=")
		envName = strings.ToUpper(envName)
		if envName == envKey || strings.HasPrefix(envName, envKey+"_") {
			return true
		}
		prefixed := "LAKEFS_" + envKey
		if envName == prefixed || strings.HasPrefix(envName, prefixed+"_") {
			return true
		}
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
	switch strings.ToLower(cfg.Type) {
	case "local":
		if cfg.Local == nil {
			return fmt.Errorf("'%s.local': %w", prefix, ErrMissingRequiredKeys)
		}
	case "s3":
		if cfg.S3 == nil {
			return fmt.Errorf("'%s.s3': %w", prefix, ErrMissingRequiredKeys)
		}
	case "gs":
		if cfg.GS == nil {
			return fmt.Errorf("'%s.gs': %w", prefix, ErrMissingRequiredKeys)
		}
	case "azure":
		if cfg.Azure == nil {
			return fmt.Errorf("'%s.azure': %w", prefix, ErrMissingRequiredKeys)
		}
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
	rawStores := canonicalStoreRawEntries()
	for i, store := range canonical.Stores {
		prefix := fmt.Sprintf("blockstores.stores[%d]", i)
		if store == nil {
			return nil, fmt.Errorf("'%s': %w", prefix, ErrBadConfiguration)
		}
		store.BlockstoreConfig = applyCanonicalStoreDefaults(store.BlockstoreConfig, rawStoreAt(rawStores, i))
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

func canonicalStoreRawEntries() []map[string]any {
	raw := viper.Get("blockstores.stores")
	switch stores := raw.(type) {
	case []map[string]any:
		out := make([]map[string]any, len(stores))
		copy(out, stores)
		return out
	case []any:
		out := make([]map[string]any, 0, len(stores))
		for _, store := range stores {
			out = append(out, rawMap(store))
		}
		return out
	case string:
		var out []map[string]any
		if err := json.Unmarshal([]byte(stores), &out); err == nil {
			return out
		}
	}
	return nil
}

func rawStoreAt(stores []map[string]any, index int) map[string]any {
	if index < 0 || index >= len(stores) {
		return nil
	}
	return stores[index]
}

func rawMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			if keyString, ok := key.(string); ok {
				out[keyString] = value
			}
		}
		return out
	}
	return nil
}

func rawConfigPathExists(values map[string]any, path ...string) bool {
	var current any = values
	for _, key := range path {
		currentMap := rawMap(current)
		if currentMap == nil {
			return false
		}
		found := false
		for candidate, value := range currentMap {
			if strings.EqualFold(candidate, key) {
				current = value
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func applyCanonicalStoreDefaults(cfg BlockstoreConfig, raw map[string]any) BlockstoreConfig {
	switch strings.ToLower(cfg.Type) {
	case "local":
		if cfg.Local == nil {
			cfg.Local = &BlockstoreLocal{}
		}
		if !rawConfigPathExists(raw, "local", "path") {
			cfg.Local.Path = DefaultBlockstoreLocalPath
		}
	case "s3":
		if cfg.S3 == nil {
			cfg.S3 = &BlockstoreS3{}
		}
		if !rawConfigPathExists(raw, "s3", "region") {
			cfg.S3.Region = DefaultBlockstoreS3Region
		}
		if !rawConfigPathExists(raw, "s3", "max_retries") {
			cfg.S3.MaxRetries = DefaultBlockstoreS3MaxRetries
		}
		if !rawConfigPathExists(raw, "s3", "discover_bucket_region") {
			cfg.S3.DiscoverBucketRegion = DefaultBlockstoreS3DiscoverBucketRegion
		}
		if !rawConfigPathExists(raw, "s3", "pre_signed_expiry") {
			cfg.S3.PreSignedExpiry = DefaultBlockstoreS3PreSignedExpiry
		}
		if !rawConfigPathExists(raw, "s3", "disable_pre_signed_ui") {
			cfg.S3.DisablePreSignedUI = DefaultBlockstoreS3DisablePreSignedUI
		}
		if cfg.S3.WebIdentity != nil && !rawConfigPathExists(raw, "s3", "web_identity", "session_expiry_window") {
			cfg.S3.WebIdentity.SessionExpiryWindow = DefaultBlockstoreS3WebIdentitySessionExpiryWindow
		}
	case "gs":
		if cfg.GS == nil {
			cfg.GS = &BlockstoreGS{}
		}
		if !rawConfigPathExists(raw, "gs", "s3_endpoint") {
			cfg.GS.S3Endpoint = DefaultBlockstoreGSS3Endpoint
		}
		if !rawConfigPathExists(raw, "gs", "pre_signed_expiry") {
			cfg.GS.PreSignedExpiry = DefaultBlockstoreGSPreSignedExpiry
		}
		if !rawConfigPathExists(raw, "gs", "disable_pre_signed_ui") {
			cfg.GS.DisablePreSignedUI = DefaultBlockstoreGSDisablePreSignedUI
		}
	case "azure":
		if cfg.Azure == nil {
			cfg.Azure = &BlockstoreAzure{}
		}
		if !rawConfigPathExists(raw, "azure", "try_timeout") {
			cfg.Azure.TryTimeout = DefaultBlockstoreAzureTryTimeout
		}
		if !rawConfigPathExists(raw, "azure", "pre_signed_expiry") {
			cfg.Azure.PreSignedExpiry = DefaultBlockstoreAzurePreSignedExpiry
		}
		if !rawConfigPathExists(raw, "azure", "disable_pre_signed_ui") {
			cfg.Azure.DisablePreSignedUI = DefaultBlockstoreAzureDisablePreSignedUI
		}
	}
	return cfg
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
