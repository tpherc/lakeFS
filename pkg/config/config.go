package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	apiparams "github.com/treeverse/lakefs/pkg/api/params"
	blockparams "github.com/treeverse/lakefs/pkg/block/params"
	"github.com/treeverse/lakefs/pkg/logging"
)

var (
	ErrBadConfiguration      = errors.New("bad configuration")
	ErrBadDomainNames        = fmt.Errorf("%w: domain names are prefixes", ErrBadConfiguration)
	ErrMissingRequiredKeys   = fmt.Errorf("%w: missing required keys", ErrBadConfiguration)
	ErrBadGCPCSEKValue       = fmt.Errorf("value of customer-supplied server side encryption is not a valid %d bytes AES key", gcpAESKeyLength)
	ErrGCPEncryptKeyConflict = errors.New("setting both kms and customer supplied encryption will result failure when reading/writing object")
	ErrNoStorageConfig       = errors.New("no storage config")
)

// UseLocalConfiguration set to true will add defaults that enable a lakeFS run
// without any other configuration like DB or blockstore.
const (
	UseLocalConfiguration   = "local-settings"
	QuickstartConfiguration = "quickstart"

	// SingleBlockstoreID - Represents a single blockstore system
	SingleBlockstoreID = ""
)

const (
	AuthRBACNone       = "none"
	AuthRBACSimplified = "simplified"
	AuthRBACExternal   = "external"
	AuthRBACInternal   = "internal"

	AuthLoginURLMethodRedirect = "redirect"
	AuthLoginURLMethodSelect   = "select"
)

type Logging struct {
	Format        string   `mapstructure:"format"`
	Level         string   `mapstructure:"level"`
	Output        []string `mapstructure:"output"`
	FileMaxSizeMB int      `mapstructure:"file_max_size_mb"`
	FilesKeep     int      `mapstructure:"files_keep"`
	AuditLogLevel string   `mapstructure:"audit_log_level"`
	// TraceRequestHeaders work only on 'trace' level, default is false as it may log sensitive data to the log
	TraceRequestHeaders bool `mapstructure:"trace_request_headers"`
}

// S3AuthInfo holds S3-style authentication.
type S3AuthInfo struct {
	CredentialsFile string `mapstructure:"credentials_file"`
	Profile         string
	Credentials     *struct {
		AccessKeyID     SecureString `mapstructure:"access_key_id"`
		SecretAccessKey SecureString `mapstructure:"secret_access_key"`
		SessionToken    SecureString `mapstructure:"session_token"`
	}
}

// Database - holds metadata KV configuration
type Database struct {
	// DropTables Development flag to delete tables after successful migration to KV
	DropTables bool `mapstructure:"drop_tables"`
	// Type Name of the KV Store driver DB implementation which is available according to the kv package Drivers function
	Type string `mapstructure:"type" validate:"required"`

	Local *struct {
		// Path - Local directory path to store the DB files
		Path string `mapstructure:"path"`
		// SyncWrites - Sync ensures data written to disk on each write instead of mem cache
		SyncWrites bool `mapstructure:"sync_writes"`
		// PrefetchSize - Number of elements to prefetch while iterating
		PrefetchSize int `mapstructure:"prefetch_size"`
		// EnableLogging - Enable store and badger (trace only) logging
		EnableLogging bool `mapstructure:"enable_logging"`
	} `mapstructure:"local"`

	Postgres *struct {
		ConnectionString      SecureString  `mapstructure:"connection_string"`
		MaxOpenConnections    int32         `mapstructure:"max_open_connections"`
		MaxIdleConnections    int32         `mapstructure:"max_idle_connections"`
		ConnectionMaxLifetime time.Duration `mapstructure:"connection_max_lifetime"`
		ScanPageSize          int           `mapstructure:"scan_page_size"`
		Metrics               bool          `mapstructure:"metrics"`
	}

	DynamoDB *struct {
		// The name of the DynamoDB table to be used as KV
		TableName string `mapstructure:"table_name"`

		// Maximal number of items per page during scan operation
		ScanLimit int64 `mapstructure:"scan_limit"`

		// The endpoint URL of the DynamoDB endpoint
		// Can be used to redirect to DynamoDB on AWS, local docker etc.
		Endpoint string `mapstructure:"endpoint"`

		// AWS connection details - region and credentials
		// This will override any such details that are already exist in the system
		// While in general, AWS region and credentials are configured in the system for AWS usage,
		// these can be used to specify fake values, that cna be used to connect to local DynamoDB,
		// in case there are no credentials configured in the system
		// This is a client requirement as described in section 4 in
		// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.DownloadingAndRunning.html
		AwsRegion          string       `mapstructure:"aws_region"`
		AwsProfile         string       `mapstructure:"aws_profile"`
		AwsAccessKeyID     SecureString `mapstructure:"aws_access_key_id"`
		AwsSecretAccessKey SecureString `mapstructure:"aws_secret_access_key"`

		// HealthCheckInterval - Interval to run health check for the DynamoDB instance
		// Won't run when is equal or less than 0.
		HealthCheckInterval time.Duration `mapstructure:"health_check_interval"`

		// MaxAttempts - Specifies the maximum number attempts to make on a request.
		MaxAttempts int `mapstructure:"max_attempts"`

		// Maximum amount of connections to DDB. 0 means no limit.
		MaxConnections int `mapstructure:"max_connections"`

		// CredentialsCacheExpiryWindow - The expiry window for cached credentials.
		// Default is 60 seconds.
		CredentialsCacheExpiryWindow time.Duration `mapstructure:"credentials_cache_expiry_window"`

		// CredentialsCacheExpiryWindowJitterFraction - The jitter fraction for credentials cache expiry.
		// Default is 0.5 (50% jitter).
		CredentialsCacheExpiryWindowJitterFraction float64 `mapstructure:"credentials_cache_expiry_window_jitter_fraction"`
	} `mapstructure:"dynamodb"`

	CosmosDB *struct {
		Key        SecureString `mapstructure:"key"`
		Endpoint   string       `mapstructure:"endpoint"`
		Database   string       `mapstructure:"database"`
		Container  string       `mapstructure:"container"`
		Throughput int32        `mapstructure:"throughput"`
		Autoscale  bool         `mapstructure:"autoscale"`
	} `mapstructure:"cosmosdb"`

	Redis *struct {
		Endpoint           string        `mapstructure:"endpoint"`
		Username           string        `mapstructure:"username"`
		Password           SecureString  `mapstructure:"password"`
		Database           int           `mapstructure:"database"`
		PoolSize           int           `mapstructure:"pool_size"`
		MinIdleConns       int           `mapstructure:"min_idle_conns"`
		DialTimeout        time.Duration `mapstructure:"dial_timeout"`
		ReadTimeout        time.Duration `mapstructure:"read_timeout"`
		WriteTimeout       time.Duration `mapstructure:"write_timeout"`
		Namespace          string        `mapstructure:"namespace"`
		EnableTLS          bool          `mapstructure:"enable_tls"`
		TLSSkipVerify      bool          `mapstructure:"tls_skip_verify"`
		AWSRegion          string        `mapstructure:"aws_region"`
		AWSProfile         string        `mapstructure:"aws_profile"`
		AWSAccessKeyID     SecureString  `mapstructure:"aws_access_key_id"`
		AWSSecretAccessKey SecureString  `mapstructure:"aws_secret_access_key"`
		UseIAMAuth         bool          `mapstructure:"use_iam_auth"`
		ClusterMode        bool          `mapstructure:"cluster_mode"`
		BatchSize          int           `mapstructure:"batch_size"`
	} `mapstructure:"redis"`
}

// ApproximatelyCorrectOwnership configures an approximate ("mostly correct") ownership.
type ApproximatelyCorrectOwnership struct {
	Enabled bool          `mapstructure:"enabled"`
	Refresh time.Duration `mapstructure:"refresh"`
	Acquire time.Duration `mapstructure:"acquire"`
}

// AdapterConfig configures a blockstore adapter.
type AdapterConfig interface {
	BlockstoreType() string
	BlockstoreDescription() string
	BlockstoreLocalParams() (blockparams.Local, error)
	BlockstoreS3Params() (blockparams.S3, error)
	BlockstoreGSParams() (blockparams.GS, error)
	BlockstoreAzureParams() (blockparams.Azure, error)
	GetDefaultNamespacePrefix() *string
	IsBackwardsCompatible() bool
	ID() string
}

type BlockstoreLocal struct {
	Path                    string   `mapstructure:"path"`
	ImportEnabled           bool     `mapstructure:"import_enabled"`
	ImportHidden            bool     `mapstructure:"import_hidden"`
	AllowedExternalPrefixes []string `mapstructure:"allowed_external_prefixes"`
}

type BlockstoreS3WebIdentity struct {
	SessionDuration     time.Duration `mapstructure:"session_duration"`
	SessionExpiryWindow time.Duration `mapstructure:"session_expiry_window"`
}

type BlockstoreS3 struct {
	S3AuthInfo                    `mapstructure:",squash"`
	Region                        string        `mapstructure:"region"`
	Endpoint                      string        `mapstructure:"endpoint"`
	MaxRetries                    int           `mapstructure:"max_retries"`
	ForcePathStyle                bool          `mapstructure:"force_path_style"`
	DiscoverBucketRegion          bool          `mapstructure:"discover_bucket_region"`
	SkipVerifyCertificateTestOnly bool          `mapstructure:"skip_verify_certificate_test_only"`
	ServerSideEncryption          string        `mapstructure:"server_side_encryption"`
	ServerSideEncryptionKmsKeyID  string        `mapstructure:"server_side_encryption_kms_key_id"`
	PreSignedExpiry               time.Duration `mapstructure:"pre_signed_expiry"`
	// Endpoint for pre-signed URLs, if set, will override the default pre-signed URL S3 endpoint (only for pre-sign URL generation)
	PreSignedEndpoint         string                   `mapstructure:"pre_signed_endpoint"`
	DisablePreSigned          bool                     `mapstructure:"disable_pre_signed"`
	DisablePreSignedUI        bool                     `mapstructure:"disable_pre_signed_ui"`
	DisablePreSignedMultipart bool                     `mapstructure:"disable_pre_signed_multipart"`
	ClientLogRetries          bool                     `mapstructure:"client_log_retries"`
	ClientLogRequest          bool                     `mapstructure:"client_log_request"`
	WebIdentity               *BlockstoreS3WebIdentity `mapstructure:"web_identity"`
}

type BlockstoreAzure struct {
	TryTimeout       time.Duration `mapstructure:"try_timeout"`
	StorageAccount   string        `mapstructure:"storage_account"`
	StorageAccessKey string        `mapstructure:"storage_access_key"`
	// Deprecated: Value ignored
	AuthMethodDeprecated string        `mapstructure:"auth_method"`
	PreSignedExpiry      time.Duration `mapstructure:"pre_signed_expiry"`
	DisablePreSigned     bool          `mapstructure:"disable_pre_signed"`
	DisablePreSignedUI   bool          `mapstructure:"disable_pre_signed_ui"`
	// Deprecated: Value ignored
	ChinaCloudDeprecated bool   `mapstructure:"china_cloud"`
	TestEndpointURL      string `mapstructure:"test_endpoint_url"`
	// Domain by default points to Azure default domain blob.core.windows.net, can be set to other Azure domains (China/Gov)
	Domain string `mapstructure:"domain"`
}
type BlockstoreGS struct {
	S3Endpoint                           string        `mapstructure:"s3_endpoint"`
	CredentialsFile                      string        `mapstructure:"credentials_file"`
	CredentialsJSON                      string        `mapstructure:"credentials_json"`
	PreSignedExpiry                      time.Duration `mapstructure:"pre_signed_expiry"`
	DisablePreSigned                     bool          `mapstructure:"disable_pre_signed"`
	DisablePreSignedUI                   bool          `mapstructure:"disable_pre_signed_ui"`
	ServerSideEncryptionCustomerSupplied string        `mapstructure:"server_side_encryption_customer_supplied"`
	ServerSideEncryptionKmsKeyID         string        `mapstructure:"server_side_encryption_kms_key_id"`

	// Dual adapter configuration for network-restricted access **experimental**
	DataCredentialsFile string `mapstructure:"data_credentials_file"`
	DataCredentialsJSON string `mapstructure:"data_credentials_json"`
}

// BlockstoreConfig contains block adapter settings shared by single-storage
// mode and each named multi-storage entry.
type BlockstoreConfig struct {
	Type                   string           `mapstructure:"type"`
	DefaultNamespacePrefix *string          `mapstructure:"default_namespace_prefix"`
	Local                  *BlockstoreLocal `mapstructure:"local"`
	S3                     *BlockstoreS3    `mapstructure:"s3"`
	Azure                  *BlockstoreAzure `mapstructure:"azure"`
	GS                     *BlockstoreGS    `mapstructure:"gs"`
}

// BlockstoreStorage configures one resolved named storage backend.
type BlockstoreStorage struct {
	BlockstoreConfig   `mapstructure:",squash"`
	Description        string `mapstructure:"description"`
	BackwardCompatible bool   `mapstructure:"backward_compatible"`
	storageID          string
}

// BlockstoreStore is one canonical blockstores.stores[] entry.
type BlockstoreStore struct {
	ID                string `mapstructure:"id"`
	BlockstoreStorage `mapstructure:",squash"`
}

// Blockstores is the documented multi-storage registry. Backends are loaded
// during startup; they are not API-managed lakeFS resources.
type Blockstores struct {
	Signing struct {
		SecretKey SecureString `mapstructure:"secret_key"`
	} `mapstructure:"signing"`
	Stores []*BlockstoreStore `mapstructure:"stores"`
}

type Blockstore struct {
	Signing struct {
		SecretKey SecureString `mapstructure:"secret_key"`
	} `mapstructure:"signing"`
	BlockstoreConfig `mapstructure:",squash"`

	storages            map[string]*BlockstoreStorage
	storageIDs          []string
	compatibleStorageID string
}

func (b *Blockstore) GetStorageIDs() []string {
	if len(b.storages) > 0 {
		storageIDs := make([]string, len(b.storageIDs))
		copy(storageIDs, b.storageIDs)
		return storageIDs
	}
	return []string{SingleBlockstoreID}
}

func (b *Blockstore) GetStorageByID(id string) AdapterConfig {
	if len(b.storages) > 0 {
		storage, ok := b.storages[id]
		if !ok || storage == nil {
			return nil
		}
		return storage
	}
	if id != SingleBlockstoreID {
		return nil
	}

	return b
}

func (b *Blockstore) BlockstoreType() string {
	return b.Type
}

func blockstoreS3Params(cfg *BlockstoreConfig) (blockparams.S3, error) {
	var webIdentity *blockparams.S3WebIdentity
	if cfg.S3.WebIdentity != nil {
		webIdentity = &blockparams.S3WebIdentity{
			SessionDuration:     cfg.S3.WebIdentity.SessionDuration,
			SessionExpiryWindow: cfg.S3.WebIdentity.SessionExpiryWindow,
		}
	}

	var creds blockparams.S3Credentials
	if cfg.S3.Credentials != nil {
		creds.AccessKeyID = cfg.S3.Credentials.AccessKeyID.SecureValue()
		creds.SecretAccessKey = cfg.S3.Credentials.SecretAccessKey.SecureValue()
		creds.SessionToken = cfg.S3.Credentials.SessionToken.SecureValue()
	}

	return blockparams.S3{
		Region:                        cfg.S3.Region,
		Profile:                       cfg.S3.Profile,
		CredentialsFile:               cfg.S3.CredentialsFile,
		Credentials:                   creds,
		MaxRetries:                    cfg.S3.MaxRetries,
		Endpoint:                      cfg.S3.Endpoint,
		ForcePathStyle:                cfg.S3.ForcePathStyle,
		DiscoverBucketRegion:          cfg.S3.DiscoverBucketRegion,
		SkipVerifyCertificateTestOnly: cfg.S3.SkipVerifyCertificateTestOnly,
		ServerSideEncryption:          cfg.S3.ServerSideEncryption,
		ServerSideEncryptionKmsKeyID:  cfg.S3.ServerSideEncryptionKmsKeyID,
		PreSignedExpiry:               cfg.S3.PreSignedExpiry,
		PreSignedEndpoint:             cfg.S3.PreSignedEndpoint,
		DisablePreSigned:              cfg.S3.DisablePreSigned,
		DisablePreSignedUI:            cfg.S3.DisablePreSignedUI,
		DisablePreSignedMultipart:     cfg.S3.DisablePreSignedMultipart,
		ClientLogRetries:              cfg.S3.ClientLogRetries,
		ClientLogRequest:              cfg.S3.ClientLogRequest,
		WebIdentity:                   webIdentity,
	}, nil
}

func (b *Blockstore) BlockstoreS3Params() (blockparams.S3, error) {
	return blockstoreS3Params(&b.BlockstoreConfig)
}

func (b *BlockstoreStorage) BlockstoreS3Params() (blockparams.S3, error) {
	return blockstoreS3Params(&b.BlockstoreConfig)
}

func blockstoreLocalParams(cfg *BlockstoreConfig) (blockparams.Local, error) {
	localPath := cfg.Local.Path
	path, err := homedir.Expand(localPath)
	if err != nil {
		return blockparams.Local{}, fmt.Errorf("parse blockstore location URI %s: %w", localPath, err)
	}

	params := blockparams.Local(*cfg.Local)
	params.Path = path
	return params, nil
}

func (b *Blockstore) BlockstoreLocalParams() (blockparams.Local, error) {
	return blockstoreLocalParams(&b.BlockstoreConfig)
}

func (b *BlockstoreStorage) BlockstoreLocalParams() (blockparams.Local, error) {
	return blockstoreLocalParams(&b.BlockstoreConfig)
}

func blockstoreGSParams(cfg *BlockstoreConfig) (blockparams.GS, error) {
	var customerSuppliedKey []byte = nil
	if cfg.GS.ServerSideEncryptionCustomerSupplied != "" {
		v, err := hex.DecodeString(cfg.GS.ServerSideEncryptionCustomerSupplied)
		if err != nil {
			return blockparams.GS{}, err
		}
		if len(v) != gcpAESKeyLength {
			return blockparams.GS{}, ErrBadGCPCSEKValue
		}
		customerSuppliedKey = v
		if cfg.GS.ServerSideEncryptionKmsKeyID != "" {
			return blockparams.GS{}, ErrGCPEncryptKeyConflict
		}
	}

	credPath, err := homedir.Expand(cfg.GS.CredentialsFile)
	if err != nil {
		return blockparams.GS{}, fmt.Errorf("parse GS credentials path '%s': %w", cfg.GS.CredentialsFile, err)
	}

	var dataCredPath string
	if cfg.GS.DataCredentialsFile != "" {
		dataCredPath, err = homedir.Expand(cfg.GS.DataCredentialsFile)
		if err != nil {
			return blockparams.GS{}, fmt.Errorf("parse GS data credentials path '%s': %w", cfg.GS.DataCredentialsFile, err)
		}
	}

	return blockparams.GS{
		CredentialsFile:                      credPath,
		CredentialsJSON:                      cfg.GS.CredentialsJSON,
		PreSignedExpiry:                      cfg.GS.PreSignedExpiry,
		DisablePreSigned:                     cfg.GS.DisablePreSigned,
		DisablePreSignedUI:                   cfg.GS.DisablePreSignedUI,
		ServerSideEncryptionCustomerSupplied: customerSuppliedKey,
		ServerSideEncryptionKmsKeyID:         cfg.GS.ServerSideEncryptionKmsKeyID,
		DataCredentialsFile:                  dataCredPath,
		DataCredentialsJSON:                  cfg.GS.DataCredentialsJSON,
	}, nil
}

func (b *Blockstore) BlockstoreGSParams() (blockparams.GS, error) {
	return blockstoreGSParams(&b.BlockstoreConfig)
}

func (b *BlockstoreStorage) BlockstoreGSParams() (blockparams.GS, error) {
	return blockstoreGSParams(&b.BlockstoreConfig)
}

func blockstoreAzureParams(cfg *BlockstoreConfig) (blockparams.Azure, error) {
	if cfg.Azure.AuthMethodDeprecated != "" {
		logging.ContextUnavailable().Warn("blockstore.azure.auth_method is deprecated. Value is no longer used.")
	}
	if cfg.Azure.ChinaCloudDeprecated {
		logging.ContextUnavailable().Warn("blockstore.azure.china_cloud is deprecated. Value is no longer used. Please pass Domain = 'blob.core.chinacloudapi.cn'")
		cfg.Azure.Domain = "blob.core.chinacloudapi.cn"
	}
	return blockparams.Azure{
		StorageAccount:     cfg.Azure.StorageAccount,
		StorageAccessKey:   cfg.Azure.StorageAccessKey,
		TryTimeout:         cfg.Azure.TryTimeout,
		PreSignedExpiry:    cfg.Azure.PreSignedExpiry,
		TestEndpointURL:    cfg.Azure.TestEndpointURL,
		Domain:             cfg.Azure.Domain,
		DisablePreSigned:   cfg.Azure.DisablePreSigned,
		DisablePreSignedUI: cfg.Azure.DisablePreSignedUI,
	}, nil
}

func (b *Blockstore) BlockstoreAzureParams() (blockparams.Azure, error) {
	return blockstoreAzureParams(&b.BlockstoreConfig)
}

func (b *BlockstoreStorage) BlockstoreAzureParams() (blockparams.Azure, error) {
	return blockstoreAzureParams(&b.BlockstoreConfig)
}

func (b *Blockstore) BlockstoreDescription() string {
	return ""
}

func (b *Blockstore) GetDefaultNamespacePrefix() *string {
	return b.DefaultNamespacePrefix
}

func (b *Blockstore) IsBackwardsCompatible() bool {
	return false
}

func (b *Blockstore) ID() string {
	return SingleBlockstoreID
}

func (b *BlockstoreStorage) BlockstoreType() string {
	return b.Type
}

func (b *BlockstoreStorage) BlockstoreDescription() string {
	return b.Description
}

func (b *BlockstoreStorage) GetDefaultNamespacePrefix() *string {
	return b.DefaultNamespacePrefix
}

func (b *BlockstoreStorage) IsBackwardsCompatible() bool {
	return b.BackwardCompatible
}

func (b *BlockstoreStorage) ID() string {
	return b.storageID
}

func (b *Blockstore) SigningKey() SecureString {
	return b.Signing.SecretKey
}

type Config interface {
	GetBaseConfig() *BaseConfig
	StorageConfig() StorageConfig
	AuthConfig() AuthConfig
	UIConfig() UIConfig
	Validate() error
	GetVersionContext() string
}

type StorageConfig interface {
	GetStorageByID(storageID string) AdapterConfig
	GetStorageIDs() []string
	ResolveNewRepositoryStorageID(storageID string) (string, error)
	ResolveStoredRepositoryStorageID(storageID string) (string, error)
	ValidateObjectStorageID(storageID string) error
	IsMultiStorage() bool
	SigningKey() SecureString
}

type AuthConfig interface {
	GetBaseAuthConfig() *BaseAuth
	GetAuthUIConfig() *AuthUIConfig
	GetLoginURLMethodConfigParam() string
	// UseUILoginPlaceholders Added this function to the interface because its implementation requires parameters from both BaseAuth and
	// AuthUIConfig, so neither struct alone could implement it.
	UseUILoginPlaceholders() bool
}

type UIConfig interface {
	IsUIEnabled() bool
	GetSnippets() []apiparams.CodeSnippet
	GetCustomViewers() []apiparams.CustomViewer
}

type Features struct {
	LocalRBAC bool `mapstructure:"local_rbac"`
}

// BaseConfig - Output struct of configuration, used to validate.  If you read a key using a viper accessor
// rather than accessing a field of this struct, that key will *not* be validated.  So don't
// do that.
type BaseConfig struct {
	ListenAddress string `mapstructure:"listen_address"`
	TLS           struct {
		Enabled  bool   `mapstructure:"enabled"`
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
	} `mapstructure:"tls"`

	Actions struct {
		// ActionsEnabled set to false will block any hook execution
		Enabled bool `mapstructure:"enabled"`
		Lua     struct {
			NetHTTPEnabled bool `mapstructure:"net_http_enabled"`
		} `mapstructure:"lua"`
		Env struct {
			Enabled bool   `mapstructure:"enabled"`
			Prefix  string `mapstructure:"prefix"`
		} `mapstructure:"env"`
	} `mapstructure:"actions"`
	Logging     Logging     `mapstructure:"logging"`
	Database    Database    `mapstructure:"database"`
	Blockstores Blockstores `mapstructure:"blockstores"`
	Blockstore  Blockstore  `mapstructure:"blockstore"`
	Committed   struct {
		LocalCache struct {
			SizeBytes             int64   `mapstructure:"size_bytes"`
			Dir                   string  `mapstructure:"dir"`
			MaxUploadersPerWriter int     `mapstructure:"max_uploaders_per_writer"`
			RangeProportion       float64 `mapstructure:"range_proportion"`
			MetaRangeProportion   float64 `mapstructure:"metarange_proportion"`
		} `mapstructure:"local_cache"`
		BlockStoragePrefix string `mapstructure:"block_storage_prefix"`
		Permanent          struct {
			MinRangeSizeBytes      uint64  `mapstructure:"min_range_size_bytes"`
			MaxRangeSizeBytes      uint64  `mapstructure:"max_range_size_bytes"`
			RangeRaggednessEntries float64 `mapstructure:"range_raggedness_entries"`
		} `mapstructure:"permanent"`
		SSTable struct {
			Memory struct {
				CacheSizeBytes int64 `mapstructure:"cache_size_bytes"`
			} `mapstructure:"memory"`
		} `mapstructure:"sstable"`
	} `mapstructure:"committed"`
	UGC struct {
		PrepareMaxFileSize int64         `mapstructure:"prepare_max_file_size"`
		PrepareInterval    time.Duration `mapstructure:"prepare_interval"`
	} `mapstructure:"ugc"`
	Graveler struct {
		EnsureReadableRootNamespace bool `mapstructure:"ensure_readable_root_namespace"`
		BatchDBIOTransactionMarkers bool `mapstructure:"batch_dbio_transaction_markers"`
		CompactionSensorThreshold   int  `mapstructure:"compaction_sensor_threshold"`
		RepositoryCache             struct {
			Size   int           `mapstructure:"size"`
			Expiry time.Duration `mapstructure:"expiry"`
			Jitter time.Duration `mapstructure:"jitter"`
		} `mapstructure:"repository_cache"`
		CommitCache struct {
			Size   int           `mapstructure:"size"`
			Expiry time.Duration `mapstructure:"expiry"`
			Jitter time.Duration `mapstructure:"jitter"`
		} `mapstructure:"commit_cache"`
		Background struct {
			RateLimit int `mapstructure:"rate_limit"`
		} `mapstructure:"background"`
		MaxBatchDelay time.Duration `mapstructure:"max_batch_delay"`
		// Parameters for tuning performance of concurrent branch
		// update operations.  These do not affect correctness or
		// liveness.  Internally this is "*most correct* branch
		// ownership" because this ownership may safely fail.  This
		// distinction is unimportant during configuration, so use a
		// shorter name.
		BranchOwnership ApproximatelyCorrectOwnership `mapstructure:"branch_ownership"`
	} `mapstructure:"graveler"`
	Gateways struct {
		S3 struct {
			DomainNames       Strings `mapstructure:"domain_name"`
			Region            string  `mapstructure:"region"`
			FallbackURL       string  `mapstructure:"fallback_url"`
			VerifyUnsupported bool    `mapstructure:"verify_unsupported"`
		} `mapstructure:"s3"`
	}
	Stats struct {
		Enabled       bool          `mapstructure:"enabled"`
		Address       string        `mapstructure:"address"`
		FlushInterval time.Duration `mapstructure:"flush_interval"`
		FlushSize     int           `mapstructure:"flush_size"`
		Extended      bool          `mapstructure:"extended"`
	} `mapstructure:"stats"`
	EmailSubscription struct {
		Enabled bool `mapstructure:"enabled"`
	} `mapstructure:"email_subscription"`
	Installation struct {
		FixedID                 string       `mapstructure:"fixed_id"`
		UserName                string       `mapstructure:"user_name"`
		AccessKeyID             SecureString `mapstructure:"access_key_id"`
		SecretAccessKey         SecureString `mapstructure:"secret_access_key"`
		AllowInterRegionStorage bool         `mapstructure:"allow_inter_region_storage"`
	} `mapstructure:"installation"`
	Security struct {
		CheckLatestVersion      bool          `mapstructure:"check_latest_version"`
		CheckLatestVersionCache time.Duration `mapstructure:"check_latest_version_cache"`
		AuditCheckInterval      time.Duration `mapstructure:"audit_check_interval"`
		AuditCheckURL           string        `mapstructure:"audit_check_url"`
	} `mapstructure:"security"`
	UsageReport struct {
		// Deprecated: Value ignored
		EnabledDeprecated bool          `mapstructure:"enabled"`
		FlushInterval     time.Duration `mapstructure:"flush_interval"`
	} `mapstructure:"usage_report"`
	Features Features `mapstructure:"features"`
}

func (c *BaseConfig) GetVersionContext() string {
	return "lakeFS"
}

func ValidateBlockstore(c *Blockstore) error {
	if c.Signing.SecretKey == "" {
		return fmt.Errorf("'blockstore.signing.secret_key': %w", ErrMissingRequiredKeys)
	}
	if !c.IsMultiStorage() {
		return validateStorageEntry("blockstore", &c.BlockstoreConfig)
	}
	compatibleCount := 0
	for _, id := range c.GetStorageIDs() {
		storage := c.storages[id]
		if id == "" || !storageIDRegexp.MatchString(id) {
			return fmt.Errorf("'blockstores.stores.id': %w", ErrBadConfiguration)
		}
		if storage == nil {
			return fmt.Errorf("'blockstores.stores.%s': %w", id, ErrBadConfiguration)
		}
		if err := validateStorageEntry("blockstores.stores."+id, &storage.BlockstoreConfig); err != nil {
			return err
		}
		if storage.BackwardCompatible {
			compatibleCount++
		}
	}
	if compatibleCount > 1 {
		return fmt.Errorf("'blockstores.stores.backward_compatible': %w", ErrBadConfiguration)
	}
	return nil
}

// NewConfig - General (common) configuration
func NewConfig(cfgType string, c Config) (*BaseConfig, error) {
	oidcProviderInConfig := viper.InConfig("auth.providers.oidc")
	// Inform viper of all expected fields.  Otherwise, it fails to deserialize from the
	// environment.
	storageSource := detectStorageConfigSource()
	SetDefaults(cfgType, c)
	err := Unmarshal(c)
	if err != nil {
		return nil, err
	}
	preserveConfiguredProviderBlocks(c, oidcProviderInConfig)

	cfg := c.GetBaseConfig()
	resolvedStorage, err := ResolveBlockstoreConfig(&cfg.Blockstore, &cfg.Blockstores, storageSource)
	if err != nil {
		return nil, err
	}
	cfg.Blockstore = *resolvedStorage
	// setup logging package
	logging.SetOutputFormat(cfg.Logging.Format)
	err = logging.SetOutputs(cfg.Logging.Output, cfg.Logging.FileMaxSizeMB, cfg.Logging.FilesKeep)
	if err != nil {
		return nil, err
	}
	logging.SetLevel(cfg.Logging.Level)
	return cfg, nil
}

func SetDefaults(cfgType string, c Config) {
	keys := GetStructKeys(reflect.TypeOf(c), "mapstructure", "squash")
	for _, key := range keys {
		viper.SetDefault(key, nil)
	}
	setBaseDefaults(cfgType)
}

func Unmarshal(c Config) error {
	return viper.UnmarshalExact(&c, DecoderConfig())
}

func preserveConfiguredProviderBlocks(c Config, oidcProviderInConfig bool) {
	if !oidcProviderInConfig {
		return
	}
	baseAuthCfg := c.AuthConfig().GetBaseAuthConfig()
	if baseAuthCfg.Providers.OIDC == nil {
		baseAuthCfg.Providers.OIDC = &OIDCProvider{}
	}
}

func DecoderConfig() viper.DecoderConfigOption {
	hook := viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			DecodeStrings,
			mapstructure.StringToTimeDurationHookFunc(),
			DecodeStringToMap(),
			StringToStructHookFunc(),
			StringToSliceWithBracketHookFunc(),
		))
	return hook
}

func stringReverse(s string) string {
	chars := []rune(s)
	for i := 0; i < len(chars)/2; i++ {
		j := len(chars) - 1 - i
		chars[i], chars[j] = chars[j], chars[i]
	}
	return string(chars)
}

func (c *BaseConfig) ValidateDomainNames() error {
	domainStrings := c.Gateways.S3.DomainNames
	domainNames := make([]string, len(domainStrings))
	copy(domainNames, domainStrings)
	for i, d := range domainNames {
		domainNames[i] = stringReverse(d)
	}
	sort.Strings(domainNames)
	for i, d := range domainNames {
		domainNames[i] = stringReverse(d)
	}
	for i := 0; i < len(domainNames)-1; i++ {
		if strings.HasSuffix(domainNames[i+1], "."+domainNames[i]) {
			return fmt.Errorf("%w: %s, %s", ErrBadDomainNames, domainNames[i], domainNames[i+1])
		}
	}
	return nil
}

func (c *BaseConfig) GetBaseConfig() *BaseConfig {
	return c
}

func (c *BaseConfig) StorageConfig() StorageConfig {
	return &c.Blockstore
}

func (c *BaseConfig) Validate() error {
	missingKeys := ValidateMissingRequiredKeys(c, "mapstructure", "squash")
	if len(missingKeys) > 0 {
		return fmt.Errorf("%w: %v", ErrMissingRequiredKeys, missingKeys)
	}
	return ValidateBlockstore(&c.Blockstore)
}

const (
	gcpAESKeyLength = 32
)

type BaseAuth struct {
	Cache struct {
		Enabled bool          `mapstructure:"enabled"`
		Size    int           `mapstructure:"size"`
		TTL     time.Duration `mapstructure:"ttl"`
		Jitter  time.Duration `mapstructure:"jitter"`
	} `mapstructure:"cache"`
	Encrypt struct {
		SecretKey SecureString `mapstructure:"secret_key" validate:"required"`
	} `mapstructure:"encrypt"`
	API struct {
		// Endpoint for authorization operations
		Endpoint           string        `mapstructure:"endpoint"`
		Token              SecureString  `mapstructure:"token"`
		SupportsInvites    bool          `mapstructure:"supports_invites"`
		HealthCheckTimeout time.Duration `mapstructure:"health_check_timeout"`
		SkipHealthCheck    bool          `mapstructure:"skip_health_check"`
	} `mapstructure:"api"`
	AuthenticationAPI struct {
		// Endpoint for authentication operations
		Endpoint string `mapstructure:"endpoint"`
		// ExternalPrincipalAuth configuration related external principals
		ExternalPrincipalsEnabled bool `mapstructure:"external_principals_enabled"`
	} `mapstructure:"authentication_api"`
	RemoteAuthenticator struct {
		// Enabled if set true will enable remote authentication
		Enabled bool `mapstructure:"enabled"`
		// Endpoint URL of the remote authentication service (e.g. https://my-auth.example.com/auth)
		Endpoint string `mapstructure:"endpoint"`
		// DefaultUserGroup is the default group for the users authenticated by the remote service
		DefaultUserGroup string `mapstructure:"default_user_group"`
		// RequestTimeout timeout for remote authentication requests
		RequestTimeout time.Duration `mapstructure:"request_timeout"`
	} `mapstructure:"remote_authenticator"`
	OIDC                   OIDC                   `mapstructure:"oidc"`
	Providers              AuthProviders          `mapstructure:"providers"`
	CookieAuthVerification CookieAuthVerification `mapstructure:"cookie_auth_verification"`
	// LogoutRedirectURL is the URL on which to mount the
	// server-side logout.
	LogoutRedirectURL string        `mapstructure:"logout_redirect_url"`
	LoginDuration     time.Duration `mapstructure:"login_duration"`
	LoginMaxDuration  time.Duration `mapstructure:"login_max_duration"`
}

type AuthUIConfig struct {
	RBAC                 string   `mapstructure:"rbac"`
	LoginURL             string   `mapstructure:"login_url"`
	LoginURLMethod       string   `mapstructure:"login_url_method"`
	LoginFailedMessage   string   `mapstructure:"login_failed_message"`
	FallbackLoginURL     *string  `mapstructure:"fallback_login_url"`
	FallbackLoginLabel   *string  `mapstructure:"fallback_login_label"`
	LoginCookieNames     []string `mapstructure:"login_cookie_names"`
	LogoutURL            string   `mapstructure:"logout_url"`
	UseLoginPlaceholders bool     `mapstructure:"use_login_placeholders"`
}

type Auth struct {
	BaseAuth     `mapstructure:",squash"`
	AuthUIConfig `mapstructure:"ui_config"`
}

type AuthProviders struct {
	OIDC *OIDCProvider `mapstructure:"oidc"`
}

type OIDCProvider struct {
	URL                              string            `mapstructure:"url"`
	ClientID                         string            `mapstructure:"client_id"`
	ClientSecret                     SecureString      `mapstructure:"client_secret"`
	CallbackBaseURL                  string            `mapstructure:"callback_base_url"`
	CallbackBaseURLs                 []string          `mapstructure:"callback_base_urls"`
	AuthorizeEndpointQueryParameters map[string]string `mapstructure:"authorize_endpoint_query_parameters"`
	LogoutEndpointQueryParameters    []string          `mapstructure:"logout_endpoint_query_parameters"`
	LogoutClientIDQueryParameter     string            `mapstructure:"logout_client_id_query_parameter"`
	AdditionalScopeClaims            []string          `mapstructure:"additional_scope_claims"`
	PostLoginRedirectURL             string            `mapstructure:"post_login_redirect_url"`
}

func (p *OIDCProvider) IsConfigured() bool {
	return p != nil
}

type OIDC struct {
	// configure how users are handled on the lakeFS side:
	ValidateIDTokenClaims  map[string]string `mapstructure:"validate_id_token_claims"`
	DefaultInitialGroups   []string          `mapstructure:"default_initial_groups"`
	InitialGroupsClaimName string            `mapstructure:"initial_groups_claim_name"`
	FriendlyNameClaimName  string            `mapstructure:"friendly_name_claim_name"`
	EmailClaimName         string            `mapstructure:"email_claim_name"`
	PersistFriendlyName    bool              `mapstructure:"persist_friendly_name"`
}

// CookieAuthVerification is related to auth based on a cookie set by an external service
// TODO(isan) consolidate with OIDC
type CookieAuthVerification struct {
	// ValidateIDTokenClaims if set will validate the values (e.g., department: "R&D") exist in the token claims
	ValidateIDTokenClaims map[string]string `mapstructure:"validate_id_token_claims"`
	// DefaultInitialGroups is a list of groups to add to the user on the lakeFS side
	DefaultInitialGroups []string `mapstructure:"default_initial_groups"`
	// InitialGroupsClaimName comma separated list of groups to add to the user on the lakeFS side
	InitialGroupsClaimName string `mapstructure:"initial_groups_claim_name"`
	// FriendlyNameClaimName is the claim name to use as the user's friendly name in places like the UI
	FriendlyNameClaimName string `mapstructure:"friendly_name_claim_name"`
	// ExternalUserIDClaimName is the claim name to use as the user identifier with an IDP
	ExternalUserIDClaimName string `mapstructure:"external_user_id_claim_name"`
	// AuthSource tag each user with label of the IDP
	AuthSource string `mapstructure:"auth_source"`
	// PersistFriendlyName should we persist the friendly name in the KV store
	PersistFriendlyName bool `mapstructure:"persist_friendly_name"`
}

func (a *Auth) GetBaseAuthConfig() *BaseAuth {
	return &a.BaseAuth
}

func (a *Auth) GetAuthUIConfig() *AuthUIConfig {
	return &a.AuthUIConfig
}

func (a *Auth) GetLoginURLMethodConfigParam() string {
	if a.LoginURL == "" {
		return "none"
	}
	if a.LoginURLMethod == "" {
		return AuthLoginURLMethodRedirect
	}
	return a.LoginURLMethod
}

func (a *Auth) Validate() error {
	if a.IsAuthenticationTypeAPI() && a.Providers.OIDC.IsConfigured() {
		return fmt.Errorf("%w: auth.authentication_api and auth.providers.oidc are mutually exclusive", ErrBadConfiguration)
	}
	switch a.LoginURLMethod {
	case "", AuthLoginURLMethodRedirect, AuthLoginURLMethodSelect:
		if a.Providers.OIDC != nil {
			return a.Providers.OIDC.Validate()
		}
		return nil
	default:
		return fmt.Errorf("%w: auth.ui_config.login_url_method must be %q or %q", ErrBadConfiguration, AuthLoginURLMethodRedirect, AuthLoginURLMethodSelect)
	}
}

// UseUILoginPlaceholders returns true if the UI should use placeholders for login
// the UI should use placeholders just in case of LDAP, the other auth methods should have their own login page
func (a *Auth) UseUILoginPlaceholders() bool {
	return a.RemoteAuthenticator.Enabled || a.UseLoginPlaceholders
}

func (b *BaseAuth) IsAuthenticationTypeAPI() bool {
	return b.AuthenticationAPI.Endpoint != ""
}

func (b *BaseAuth) IsAuthTypeAPI() bool {
	return b.API.Endpoint != ""
}

func (b *BaseAuth) IsExternalPrincipalsEnabled() bool {
	// IsAuthTypeAPI must be true since the local auth service doesn't support external principals
	// ExternalPrincipalsEnabled indicates that the remote auth service enables external principals support since its optional extension
	return b.AuthenticationAPI.ExternalPrincipalsEnabled
}

func (u *AuthUIConfig) IsAuthBasic() bool {
	return u.RBAC == AuthRBACNone
}

func (u *AuthUIConfig) IsAuthUISimplified() bool {
	return u.RBAC == AuthRBACSimplified
}

func (u *AuthUIConfig) IsAdvancedAuth() bool {
	return u.RBAC == AuthRBACExternal || u.RBAC == AuthRBACInternal
}

func (u *AuthUIConfig) UsesLocalRBAC(localRBAC bool) bool {
	return u.RBAC == AuthRBACInternal && localRBAC
}

func (u *AuthUIConfig) UsesExternalRBAC(localRBAC bool) bool {
	return u.RBAC == AuthRBACExternal || (u.RBAC == AuthRBACInternal && !localRBAC)
}

type UI struct {
	// Enabled - control serving of embedded UI
	Enabled  bool        `mapstructure:"enabled"`
	Snippets []UISnippet `mapstructure:"snippets"`
}

type UISnippet struct {
	ID   string `mapstructure:"id"`
	Code string `mapstructure:"code"`
}

func (u *UI) IsUIEnabled() bool {
	return u.Enabled
}

func (u *UI) GetSnippets() []apiparams.CodeSnippet {
	return BuildCodeSnippets(u.Snippets)
}

func BuildCodeSnippets(s []UISnippet) []apiparams.CodeSnippet {
	snippets := make([]apiparams.CodeSnippet, 0, len(s))
	for _, item := range s {
		snippets = append(snippets, apiparams.CodeSnippet{
			ID:   item.ID,
			Code: item.Code,
		})
	}
	return snippets
}

func (u *UI) GetCustomViewers() []apiparams.CustomViewer {
	return nil
}
