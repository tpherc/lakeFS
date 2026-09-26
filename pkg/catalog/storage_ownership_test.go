package catalog

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestOwnedRelativeAddress(t *testing.T) {
	t.Parallel()
	ownership := storageOwnership{
		"home":     {provider: "s3", service: "https://ecs-a.example/namespace"},
		"alias":    {provider: "s3", service: "https://ecs-a.example/namespace"},
		"foreign":  {provider: "s3", service: "https://ecs-b.example/namespace"},
		"gcs-a":    {provider: "gs", service: "gcs"},
		"gcs-b":    {provider: "gs", service: "gcs"},
		"azure-a":  {provider: "azure", service: "blob.core.windows.net"},
		"azure-b":  {provider: "azure", service: "blob.core.windows.net"},
		"azure-cn": {provider: "azure", service: "blob.core.chinacloudapi.cn"},
		"unknown":  {provider: "s3"},
	}
	tests := []struct {
		name, home, namespace, source, address, relative string
		owned                                            bool
		err                                              error
	}{
		{name: "inherited home", home: "home", namespace: "s3://bucket/repo", address: "s3://bucket/repo/data/x", relative: "data/x", owned: true},
		{name: "home full outside data subtree", home: "home", namespace: "s3://bucket/repo", address: "s3://bucket/repo/other/x", relative: "other/x", owned: true},
		{name: "s3 credential alias", home: "home", namespace: "s3://bucket/repo", source: "alias", address: "s3://bucket/repo/data/x", relative: "data/x", owned: true},
		{name: "S3 adapter with gs locator", home: "home", namespace: "s3://bucket/repo", source: "alias", address: "gs://bucket/repo/data/x", relative: "data/x", owned: true},
		{name: "S3 adapter with https locator", home: "home", namespace: "s3://bucket/repo", address: "https://bucket/repo/data/x", relative: "data/x", owned: true},
		{name: "S3 adapter rejects unsupported scheme", home: "home", namespace: "s3://bucket/repo", source: "alias", address: "ftp://bucket/repo/data/x", err: block.ErrInvalidAddress},
		{name: "S3 adapter rejects missing bucket", home: "home", namespace: "s3://bucket/repo", source: "alias", address: "s3:///repo/data/x", err: block.ErrInvalidAddress},
		{name: "same URI different S3 service", home: "home", namespace: "s3://bucket/repo", source: "foreign", address: "s3://bucket/repo/data/x"},
		{name: "sibling prefix", home: "home", namespace: "s3://bucket/repo", source: "alias", address: "s3://bucket/repository/data/x"},
		{name: "other bucket", home: "home", namespace: "s3://bucket/repo", source: "alias", address: "s3://other/repo/data/x"},
		{name: "gcs credential alias", home: "gcs-a", namespace: "gs://bucket/repo", source: "gcs-b", address: "gs://bucket/repo/data/x", relative: "data/x", owned: true},
		{name: "azure credential alias", home: "azure-a", namespace: "https://account.blob.core.windows.net/container/repo", source: "azure-b", address: "https://account.blob.core.windows.net/container/repo/data/x", relative: "data/x", owned: true},
		{name: "azure URI domain does not choose service", home: "azure-a", namespace: "https://account.blob.core.windows.net/container/repo", source: "azure-b", address: "https://account.blob.core.chinacloudapi.cn/container/repo/data/x", relative: "data/x", owned: true},
		{name: "azure account hostname case", home: "azure-a", namespace: "https://account.blob.core.windows.net/container/repo", source: "azure-b", address: "https://ACCOUNT.blob.core.windows.net/container/repo/data/x", relative: "data/x", owned: true},
		{name: "azure adapter rejects s3 locator", home: "azure-a", namespace: "https://account.blob.core.windows.net/container/repo", source: "azure-b", address: "s3://account.blob.core.windows.net/container/repo/data/x", err: block.ErrInvalidAddress},
		{name: "GCS adapter rejects s3 locator", home: "gcs-a", namespace: "gs://bucket/repo", source: "gcs-b", address: "s3://bucket/repo/data/x", err: block.ErrInvalidAddress},
		{name: "azure different configured cloud", home: "azure-a", namespace: "https://account.blob.core.windows.net/container/repo", source: "azure-cn", address: "https://account.blob.core.windows.net/container/repo/data/x"},
		{name: "azure different account", home: "azure-a", namespace: "https://account.blob.core.windows.net/container/repo", source: "azure-b", address: "https://other.blob.core.windows.net/container/repo/data/x"},
		{name: "azure different container", home: "azure-a", namespace: "https://account.blob.core.windows.net/container/repo", source: "azure-b", address: "https://account.blob.core.windows.net/other/repo/data/x"},
		{name: "removed source", home: "home", namespace: "s3://bucket/repo", source: "removed", address: "s3://bucket/repo/data/x", err: config.ErrNoStorageConfig},
		{name: "unknown service", home: "home", namespace: "s3://bucket/repo", source: "unknown", address: "s3://bucket/repo/data/x", err: ErrUnknownStorageOwnership},
		{name: "malformed address", home: "home", namespace: "s3://bucket/repo", address: "not-a-native-address", err: block.ErrInvalidAddress},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := &Catalog{ownership: ownership}
			relative, owned, err := c.OwnedRelativeAddress(&Repository{StorageID: test.home, StorageNamespace: test.namespace}, test.source, test.address)
			require.ErrorIs(t, err, test.err)
			require.Equal(t, test.owned, owned)
			require.Equal(t, test.relative, relative)
		})
	}
}

func TestS3PhysicalServiceIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct{ endpoint, region, want string }{
		{"", "us-east-1", "aws"},
		{"", "eu-west-1", "aws"},
		{"", "cn-north-1", "aws-cn"},
		{"", "us-gov-west-1", "aws-us-gov"},
		{"https://s3.amazonaws.com", "", "aws"},
		{"https://s3.eu-west-1.amazonaws.com:443/", "", "aws"},
		{"https://s3-us-west-2.amazonaws.com", "", "aws"},
		{"https://s3.dualstack.us-west-2.amazonaws.com", "", "aws"},
		{"https://s3.cn-north-1.amazonaws.com.cn", "", "aws-cn"},
		{"https://s3.us-gov-west-1.amazonaws.com", "", "aws-us-gov"},
		{"https://Namespace.EXAMPLE:443/root/", "us-east-1", "https://namespace.example/root"},
		{"https://namespace.example/another", "us-east-1", "https://namespace.example/another"},
		{"https://[2001:DB8::1]:443/", "us-east-1", "https://[2001:db8::1]"},
		{"http://[2001:db8::1]:80/root/", "us-east-1", "http://[2001:db8::1]/root"},
		{"https://[2001:db8::1]:8443/", "us-east-1", "https://[2001:db8::1]:8443"},
		{"", "", ""},
		{"https://username:secret@example.com", "", ""},
	}
	for _, test := range tests {
		t.Run(test.endpoint+test.region, func(t *testing.T) {
			require.Equal(t, test.want, s3ServiceIdentity(test.endpoint, test.region))
		})
	}
}

func TestImportOwnershipOverlap(t *testing.T) {
	t.Parallel()
	ownership := storageOwnership{
		"home":    {provider: "s3", service: "one"},
		"alias":   {provider: "s3", service: "one"},
		"foreign": {provider: "s3", service: "two"},
	}
	for _, test := range []struct {
		name, source, path, kind string
		wantError                error
	}{
		{"home object", "", "s3://bucket/repo/data/x", ImportPathTypeObject, ErrInvalidImportSource},
		{"alias object", "alias", "s3://bucket/repo/data/x", ImportPathTypeObject, ErrInvalidImportSource},
		{"S3 alias with gs locator", "alias", "gs://bucket/repo/data/x", ImportPathTypeObject, ErrInvalidImportSource},
		{"alias containing prefix", "alias", "s3://bucket/", ImportPathTypePrefix, ErrInvalidImportSource},
		{"foreign identical namespace", "foreign", "s3://bucket/repo/data/x", ImportPathTypeObject, nil},
		{"outside home", "alias", "s3://bucket/external", ImportPathTypePrefix, nil},
		{"unknown source", "removed", "s3://bucket/external", ImportPathTypePrefix, config.ErrNoStorageConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ownership.verifyImportPaths("home", "s3://bucket/repo/", ImportRequest{Paths: []ImportPath{{StorageID: test.source, Path: test.path, Type: ImportPathType(test.kind)}}})
			require.ErrorIs(t, err, test.wantError)
		})
	}
}

func TestStorageOwnershipSnapshot(t *testing.T) {
	t.Parallel()
	home := &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "s3", S3: &config.BlockstoreS3{Endpoint: "https://namespace.example", Region: "us-east-1"}}}
	alias := &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "s3", S3: &config.BlockstoreS3{Endpoint: "https://namespace.example/", Region: "eu-west-1"}}}
	azureHome := &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "azure", Azure: &config.BlockstoreAzure{Domain: "blob.core.windows.net"}}}
	azureAlias := &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "azure", Azure: &config.BlockstoreAzure{Domain: "BLOB.CORE.WINDOWS.NET"}}}
	cfg := ownershipTestConfig{stores: map[string]config.AdapterConfig{"home": home, "alias": alias, "azure-home": azureHome, "azure-alias": azureAlias}}
	ownership := newStorageOwnership(cfg)
	home.S3.Endpoint = "https://changed.example"
	delete(cfg.stores, "alias")
	same, err := ownership.sameService("home", "alias")
	require.NoError(t, err)
	require.True(t, same, "ownership must use the construction-time non-secret snapshot")
	relative, owned, err := ownership.ownedRelativeAddress("azure-home", "https://account.blob.core.windows.net/container/repo", "azure-alias", "https://account.blob.core.windows.net/container/repo/data/object")
	require.NoError(t, err)
	require.True(t, owned, "DNS domain case must preserve managed-object retention")
	require.Equal(t, "data/object", relative)
}

type ownershipTestConfig struct {
	config.StorageConfig
	stores map[string]config.AdapterConfig
}

func (c ownershipTestConfig) GetStorageIDs() []string {
	ids := make([]string, 0, len(c.stores))
	for id := range c.stores {
		ids = append(ids, id)
	}
	return ids
}
func (c ownershipTestConfig) GetStorageByID(id string) config.AdapterConfig { return c.stores[id] }

func TestStorageOwnershipSDKEndpointAmbiguity(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, profile, credentialsFile, environmentKey, environmentValue string
		ignore                                                                     bool
		unknown                                                                    bool
	}{
		{name: "global endpoint override", environmentKey: "AWS_ENDPOINT_URL", environmentValue: "https://sdk-endpoint.example", unknown: true},
		{name: "service endpoint override", environmentKey: "AWS_ENDPOINT_URL_S3", environmentValue: "https://sdk-endpoint.example", unknown: true},
		{name: "profile context", profile: "research", unknown: true},
		{name: "credentials file context", credentialsFile: "/unused/shared-credentials", unknown: true},
		{name: "environment profile", environmentKey: "AWS_PROFILE", environmentValue: "research", unknown: true},
		{name: "explicit config file", environmentKey: "AWS_CONFIG_FILE", environmentValue: "/unused/shared-config", unknown: true},
		{name: "explicit endpoint takes precedence", endpoint: "https://namespace.example", environmentKey: "AWS_ENDPOINT_URL_S3", environmentValue: "https://sdk-endpoint.example"},
		{name: "ignored SDK endpoints", profile: "research", ignore: true, environmentKey: "AWS_ENDPOINT_URL_S3", environmentValue: "https://sdk-endpoint.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, key := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"} {
				t.Setenv(key, "")
			}
			if test.environmentKey != "" {
				t.Setenv(test.environmentKey, test.environmentValue)
			}
			if test.ignore {
				t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
			}
			storage := &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "s3", S3: &config.BlockstoreS3{
				S3AuthInfo: config.S3AuthInfo{Profile: test.profile, CredentialsFile: test.credentialsFile},
				Endpoint:   test.endpoint, Region: "us-east-1",
			}}}
			ownership := newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{"home": storage, "alias": storage}})
			same, err := ownership.sameService("home", "alias")
			if test.unknown {
				require.ErrorIs(t, err, ErrUnknownStorageOwnership)
				require.False(t, same)
			} else {
				require.NoError(t, err)
				require.True(t, same)
			}
			same, err = ownership.sameService("home", "home")
			require.NoError(t, err)
			require.True(t, same, "one adapter retains its own physical context")
		})
	}
}

func TestLegacyLocalOwnershipAndImport(t *testing.T) {
	t.Parallel()
	c := &Catalog{}
	repo := &Repository{StorageNamespace: "local:///absolute/repo"}
	relative, owned, err := c.OwnedRelativeAddress(repo, "", "local:///absolute/repo/data/object")
	require.NoError(t, err)
	require.True(t, owned)
	require.Equal(t, "data/object", relative)

	for _, test := range []struct {
		path    string
		kind    ImportPathType
		overlap bool
	}{
		{"local:///absolute/external/", ImportPathTypePrefix, false},
		{"local:///absolute/repo/data/object", ImportPathTypeObject, true},
		{"local:///absolute/", ImportPathTypePrefix, true},
	} {
		err := c.ownership.verifyImportPaths("", repo.StorageNamespace, ImportRequest{Paths: []ImportPath{{Path: test.path, Type: test.kind}}})
		if test.overlap {
			require.ErrorIs(t, err, ErrInvalidImportSource)
		} else {
			require.NoError(t, err)
		}
	}
}

func s3OwnershipStorage(endpoint, presignedEndpoint string) config.AdapterConfig {
	return &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "s3", S3: &config.BlockstoreS3{
		Endpoint: endpoint, PreSignedEndpoint: presignedEndpoint, Region: "us-east-1",
	}}}
}

func TestStorageOwnershipEndpointAliases(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                        string
		homeEndpoint, homePresigned string
		sourceEndpoint              string
		sourcePresigned             string
		bridge                      bool
		owned                       bool
		err                         error
	}{
		{name: "private to public", homeEndpoint: "https://private.example", homePresigned: "https://public.example", sourceEndpoint: "https://public.example", owned: true},
		{name: "public to private", homeEndpoint: "https://public.example", sourceEndpoint: "https://private.example", sourcePresigned: "https://public.example", owned: true},
		{name: "shared presigning endpoint", homeEndpoint: "https://private.example", homePresigned: "https://public.example", sourceEndpoint: "https://private-two.example", sourcePresigned: "https://public.example", owned: true},
		{name: "transitive aliases", homeEndpoint: "https://private.example", homePresigned: "https://public.example", sourceEndpoint: "https://edge.example", bridge: true, owned: true},
		{name: "unrelated endpoints", homeEndpoint: "https://private.example", homePresigned: "https://public.example", sourceEndpoint: "https://foreign.example"},
		{name: "IPv6 default port", homeEndpoint: "https://[2001:db8::1]:443", sourceEndpoint: "https://[2001:db8::1]", owned: true},
		{name: "invalid presigning identity", homeEndpoint: "https://private.example", homePresigned: "not-an-endpoint", sourceEndpoint: "https://public.example", err: ErrUnknownStorageOwnership},
	} {
		t.Run(test.name, func(t *testing.T) {
			stores := map[string]config.AdapterConfig{
				"home":  s3OwnershipStorage(test.homeEndpoint, test.homePresigned),
				"alias": s3OwnershipStorage(test.sourceEndpoint, test.sourcePresigned),
			}
			if test.bridge {
				stores["bridge"] = s3OwnershipStorage("https://public.example", "https://edge.example")
			}
			ownership := newStorageOwnership(ownershipTestConfig{stores: stores})
			relative, owned, err := ownership.ownedRelativeAddress("home", "s3://bucket/repo", "alias", "s3://bucket/repo/data/object")
			require.ErrorIs(t, err, test.err)
			require.Equal(t, test.owned, owned)
			if test.owned {
				require.Equal(t, "data/object", relative)
				err = ownership.verifyImportPaths("home", "s3://bucket/repo", ImportRequest{Paths: []ImportPath{{StorageID: "alias", Path: "s3://bucket/repo/data/object", Type: ImportPathTypeObject}}})
				require.ErrorIs(t, err, ErrInvalidImportSource)
			}
		})
	}
}
