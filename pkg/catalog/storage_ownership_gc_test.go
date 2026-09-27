package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

type orderedGCOwnershipConfig struct {
	ownershipTestConfig
	ids []string
}

func (c orderedGCOwnershipConfig) GetStorageIDs() []string { return c.ids }

func TestGCOwnershipFingerprintDeterministicAliases(t *testing.T) {
	t.Parallel()
	stores := map[string]config.AdapterConfig{
		"home":   s3OwnershipStorage("https://private.example", "https://public.example"),
		"alias":  s3OwnershipStorage("https://public.example/", "https://edge.example"),
		"source": s3OwnershipStorage("https://edge.example", ""),
	}
	var expected string
	for _, ids := range [][]string{
		{"home", "alias", "source"}, {"source", "alias", "home"}, {"alias", "home", "source"},
	} {
		c := &Catalog{ownership: newStorageOwnership(orderedGCOwnershipConfig{ownershipTestConfig{stores: stores}, ids})}
		fingerprint := c.GCOwnershipFingerprint()
		require.Len(t, fingerprint, 64)
		if expected == "" {
			expected = fingerprint
		}
		require.Equal(t, expected, fingerprint)
		for _, id := range ids {
			descriptor, err := c.GCTargetDescriptor(&Repository{StorageID: id, StorageNamespace: "s3://bucket/repo"})
			require.NoError(t, err)
			require.Equal(t, "https://edge.example", descriptor.Service)
			require.Equal(t, []string{"https://edge.example", "https://private.example", "https://public.example"}, descriptor.Routes)
		}
	}
	// Reversing which route is primary preserves the same configured alias group.
	stores["home"] = s3OwnershipStorage("https://public.example", "https://private.example")
	require.Equal(t, expected, newStorageOwnership(ownershipTestConfig{stores: stores}).gcFingerprint())
	stores["alias"] = s3OwnershipStorage("https://public.example", "")
	require.NotEqual(t, expected, newStorageOwnership(ownershipTestConfig{stores: stores}).gcFingerprint())
}

func TestGCOwnershipFingerprintIgnoresCredentials(t *testing.T) {
	t.Parallel()
	s3Store := s3OwnershipStorage("https://private.example", "https://public.example").(*config.BlockstoreStorage)
	s3Store.S3.Credentials = &struct {
		AccessKeyID     config.SecureString `mapstructure:"access_key_id"`
		SecretAccessKey config.SecureString `mapstructure:"secret_access_key"`
		SessionToken    config.SecureString `mapstructure:"session_token"`
	}{AccessKeyID: "old-access", SecretAccessKey: "old-secret", SessionToken: "old-token"}
	azureStore := &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "azure", Azure: &config.BlockstoreAzure{StorageAccessKey: "old-azure-secret"}}}
	gsStore := &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "gs", GS: &config.BlockstoreGS{CredentialsJSON: "old-gcs-secret"}}}
	cfg := ownershipTestConfig{stores: map[string]config.AdapterConfig{"s3": s3Store, "azure": azureStore, "gs": gsStore}}
	snapshot := newStorageOwnership(cfg)
	before := snapshot.gcFingerprint()
	s3Store.S3.Credentials.AccessKeyID = "new-access"
	s3Store.S3.Credentials.SecretAccessKey = "new-secret"
	s3Store.S3.Credentials.SessionToken = "new-token"
	s3Store.S3.Profile = "rotated-profile"
	s3Store.S3.CredentialsFile = "/unused/rotated-credentials"
	azureStore.Azure.StorageAccessKey = "new-azure-secret"
	gsStore.GS.CredentialsJSON = "new-gcs-secret"
	s3Store.Description = "Updated human description"
	require.Equal(t, before, newStorageOwnership(cfg).gcFingerprint())
	descriptor, err := snapshot.gcTargetDescriptor(&Repository{StorageID: "s3", StorageNamespace: "s3://bucket/repo"})
	require.NoError(t, err)
	encoded, err := json.Marshal(descriptor)
	require.NoError(t, err)
	for _, excluded := range []string{"access", "secret", "token", "profile", "credentials"} {
		require.NotContains(t, string(encoded), excluded)
	}
	s3Store.S3.Endpoint = "https://different.example"
	require.NotEqual(t, before, newStorageOwnership(cfg).gcFingerprint())
	require.Equal(t, before, snapshot.gcFingerprint(), "snapshot must not retain mutable configuration")
}

func TestGCTargetDescriptorNativeNamespace(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, namespace string
		storage         config.AdapterConfig
		want            GCTargetDescriptor
	}{
		{
			name: "S3 raw key", namespace: "s3://bucket/repo//a%2Fb/",
			storage: s3OwnershipStorage("https://[2001:DB8::1]:443/root/", "https://public.example/root"),
			want:    GCTargetDescriptor{Provider: "s3", Service: "https://[2001:db8::1]/root", Routes: []string{"https://[2001:db8::1]/root", "https://public.example/root"}, Bucket: "bucket", NamespacePrefix: "repo//a%2Fb/"},
		},
		{
			name: "AWS explicit route and partition", namespace: "s3://bucket/",
			storage: s3OwnershipStorage("https://s3.us-east-1.amazonaws.com:443/", ""),
			want:    GCTargetDescriptor{Provider: "s3", Service: "aws", Routes: []string{"aws", "https://s3.us-east-1.amazonaws.com"}, Bucket: "bucket"},
		},
		{
			name: "GCS raw key", namespace: "gs://bucket/repo//a%2Fb/",
			storage: &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "gs", GS: &config.BlockstoreGS{}}},
			want:    GCTargetDescriptor{Provider: "gs", Service: "gcs", Routes: []string{"gcs"}, Bucket: "bucket", NamespacePrefix: "repo//a%2Fb/"},
		},
		{
			name: "Azure decoded key", namespace: "https://account.blob.core.windows.net/container/repo//a%2Fb/",
			storage: &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "azure", Azure: &config.BlockstoreAzure{}}},
			want:    GCTargetDescriptor{Provider: "azure", Service: "blob.core.windows.net", Routes: []string{"blob.core.windows.net"}, Account: "account", Container: "container", NamespacePrefix: "repo//a/b/"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.want.ResolverVersion = GCOwnershipResolverVersion
			c := &Catalog{ownership: newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{"home": test.storage}})}
			repo := &Repository{StorageID: "home", StorageNamespace: test.namespace}
			got, err := c.GCTargetDescriptor(repo)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
			got.Routes[0] = "changed"
			again, err := c.GCTargetDescriptor(repo)
			require.NoError(t, err)
			require.Equal(t, test.want, again, "descriptor must not expose mutable snapshot slices")
		})
	}
}

func TestGCTargetDescriptorRejectsUncertainIdentity(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, profile, environmentKey string
	}{
		{name: "invalid explicit endpoint", endpoint: "not-an-endpoint"},
		{name: "selected profile", profile: "research"},
		{name: "environment profile", environmentKey: "AWS_PROFILE"},
		{name: "environment default profile", environmentKey: "AWS_DEFAULT_PROFILE"},
		{name: "global endpoint override", environmentKey: "AWS_ENDPOINT_URL"},
		{name: "service endpoint override", environmentKey: "AWS_ENDPOINT_URL_S3"},
		{name: "shared config context", environmentKey: "AWS_CONFIG_FILE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")
			if test.environmentKey != "" {
				t.Setenv(test.environmentKey, "test-context")
			}
			storage := s3OwnershipStorage(test.endpoint, "").(*config.BlockstoreStorage)
			storage.S3.Profile = test.profile
			ownership := newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{"home": storage}})
			_, err := ownership.gcTargetDescriptor(&Repository{StorageID: "home", StorageNamespace: "s3://bucket/repo"})
			require.ErrorIs(t, err, ErrUnknownStorageOwnership)
			same, err := ownership.sameService("home", "home")
			require.NoError(t, err)
			require.True(t, same, "ordinary same-ID admission behavior remains unchanged")
		})
	}
	t.Run("GCS implicit emulator", func(t *testing.T) {
		t.Setenv("STORAGE_EMULATOR_HOST", "http://localhost:9000")
		ownership := newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{
			"home": &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "gs", GS: &config.BlockstoreGS{}}},
		}})
		_, err := ownership.gcTargetDescriptor(&Repository{StorageID: "home", StorageNamespace: "gs://bucket/repo"})
		require.ErrorIs(t, err, ErrUnknownStorageOwnership)
	})
}

func TestGCOwnershipGCSUniverse(t *testing.T) {
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	t.Setenv("GOOGLE_CLOUD_UNIVERSE_DOMAIN", "")
	cfg := ownershipTestConfig{stores: map[string]config.AdapterConfig{
		"gs": &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "gs", GS: &config.BlockstoreGS{}}},
		"s3": s3OwnershipStorage("https://objects.example", ""),
	}}
	nativeFingerprint := newStorageOwnership(cfg).gcFingerprint()
	gsRepo := &Repository{StorageID: "gs", StorageNamespace: "gs://bucket/repo"}
	s3Repo := &Repository{StorageID: "s3", StorageNamespace: "s3://bucket/repo"}
	for _, test := range []struct {
		name, universe string
		unknown        bool
	}{
		{name: "default"},
		{name: "explicit standard service", universe: "googleapis.com"},
		{name: "alternate universe", universe: "alternate.example", unknown: true},
		{name: "unrecognized service spelling", universe: "GOOGLEAPIS.COM", unknown: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("GOOGLE_CLOUD_UNIVERSE_DOMAIN", test.universe)
			c := &Catalog{ownership: newStorageOwnership(cfg)}
			_, targetErr := c.GCTargetDescriptor(gsRepo)
			_, sameIDOwned, sameIDErr := c.GCOwnedRelativeAddress(gsRepo, "gs", "gs://bucket/repo/data/object")
			_, externalOwned, sourceErr := c.GCOwnedRelativeAddress(s3Repo, "gs", "gs://bucket/repo/data/object")
			require.False(t, externalOwned)
			if test.unknown {
				require.ErrorIs(t, targetErr, ErrUnknownStorageOwnership)
				require.ErrorIs(t, sameIDErr, ErrUnknownStorageOwnership)
				require.ErrorIs(t, sourceErr, ErrUnknownStorageOwnership)
				require.False(t, sameIDOwned)
				require.NotEqual(t, nativeFingerprint, c.GCOwnershipFingerprint())
			} else {
				require.NoError(t, targetErr)
				require.NoError(t, sameIDErr)
				require.NoError(t, sourceErr)
				require.True(t, sameIDOwned)
				require.Equal(t, nativeFingerprint, c.GCOwnershipFingerprint())
			}
		})
	}
}

func TestGCTargetDescriptorRejectsUncertifiedRoutesAndNamespaces(t *testing.T) {
	t.Parallel()
	ownership := newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{
		"home": s3OwnershipStorage("https://private.example", ""),
	}})
	_, err := ownership.gcTargetDescriptor(&Repository{StorageID: "missing", StorageNamespace: "s3://bucket/repo"})
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
	for _, namespace := range []string{"not-an-address", "s3:///repo", "s3://user@bucket/repo", "s3://bucket/repo?version=x", "ftp://bucket/repo"} {
		_, err := ownership.gcTargetDescriptor(&Repository{StorageID: "home", StorageNamespace: namespace})
		require.ErrorIs(t, err, block.ErrInvalidAddress, namespace)
	}
	unknown := storageOwnership{"home": {provider: "s3", service: "https://private.example"}}
	_, err = unknown.gcTargetDescriptor(&Repository{StorageID: "home", StorageNamespace: "s3://bucket/repo"})
	require.ErrorIs(t, err, ErrUnknownStorageOwnership, "a service label without configured routes is not sufficient")
	known := ownership.gcFingerprint()
	ownership["unknown"] = physicalService{provider: "s3"}
	require.NotEqual(t, known, ownership.gcFingerprint(), "installation scope includes unknown mappings")
}

func TestGCOwnedRelativeAddressRejectsUnknownSources(t *testing.T) {
	t.Parallel()
	c := &Catalog{ownership: storageOwnership{
		"home":              {provider: "s3", service: "https://private.example", routes: []string{"https://private.example"}},
		"known-external":    {provider: "gs", service: "gcs", routes: []string{"gcs"}},
		"implicit-emulator": {provider: "gs", service: "gcs", routes: []string{"gcs"}, gcUnknown: true},
		"unknown-service":   {provider: "s3"},
		"uncertified":       {provider: "s3", service: "https://private.example"},
	}}
	repo := &Repository{StorageID: "home", StorageNamespace: "s3://bucket/repo"}
	for _, source := range []string{"implicit-emulator", "unknown-service", "uncertified"} {
		_, owned, err := c.GCOwnedRelativeAddress(repo, source, "s3://bucket/repo/data/object")
		require.ErrorIs(t, err, ErrUnknownStorageOwnership, source)
		require.False(t, owned)
	}
	_, owned, err := c.GCOwnedRelativeAddress(repo, "missing", "s3://bucket/repo/data/object")
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
	require.False(t, owned)
	_, owned, err = c.GCOwnedRelativeAddress(repo, "known-external", "gs://bucket/repo/data/object")
	require.NoError(t, err)
	require.False(t, owned)
	relative, owned, err := c.GCOwnedRelativeAddress(repo, "", "s3://bucket/repo/data/object")
	require.NoError(t, err)
	require.True(t, owned)
	require.Equal(t, "data/object", relative)
	for _, home := range []string{"unknown-service", "implicit-emulator"} {
		_, owned, err = c.GCOwnedRelativeAddress(&Repository{StorageID: home, StorageNamespace: "s3://bucket/repo"}, home, "s3://bucket/repo/data/object")
		require.ErrorIs(t, err, ErrUnknownStorageOwnership, "same-ID comparison must not certify unknown ownership")
		require.False(t, owned)
	}
}

func TestGCOwnershipS3ConfiguredEndpoints(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, endpoint, presigned, service string
	}{
		{name: "custom endpoint", endpoint: "https://objects.example", service: "https://objects.example"},
		{name: "native AWS endpoint", endpoint: "https://s3.us-east-1.amazonaws.com", service: "aws"},
		{name: "native China endpoint", endpoint: "https://s3.cn-north-1.amazonaws.com.cn", service: "aws-cn"},
		{name: "native GovCloud endpoint", endpoint: "https://s3.us-gov-west-1.amazonaws.com", service: "aws-us-gov"},
		{name: "custom port", endpoint: "https://s3.us-east-1.amazonaws.com:8443", service: "https://s3.us-east-1.amazonaws.com:8443"},
		{name: "custom path", endpoint: "https://s3.us-east-1.amazonaws.com/tenant", service: "https://s3.us-east-1.amazonaws.com/tenant"},
		{name: "custom signing route", endpoint: "https://s3.us-east-1.amazonaws.com", presigned: "https://signed.example", service: "aws"},
		{name: "native signing alias", endpoint: "https://objects.example", presigned: "https://s3.us-east-1.amazonaws.com", service: "aws"},
		{name: "malformed endpoint", endpoint: "not-an-endpoint"},
		{name: "malformed signing route", endpoint: "https://objects.example", presigned: "not-an-endpoint"},
	} {
		t.Run(test.name, func(t *testing.T) {
			storage := s3OwnershipStorage(test.endpoint, test.presigned)
			c := &Catalog{ownership: newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{"home": storage}})}
			repo := &Repository{StorageID: "home", StorageNamespace: "s3://bucket/repo"}
			descriptor, targetErr := c.GCTargetDescriptor(repo)
			key, owned, sourceErr := c.GCOwnedRelativeAddress(repo, "home", "s3://bucket/repo/data/object")
			if test.service == "" {
				require.ErrorIs(t, targetErr, ErrUnknownStorageOwnership)
				require.ErrorIs(t, sourceErr, ErrUnknownStorageOwnership)
				require.False(t, owned)
				return
			}
			require.NoError(t, targetErr)
			require.Equal(t, test.service, descriptor.Service)
			require.Contains(t, descriptor.Routes, normalizedServiceEndpoint(test.endpoint))
			require.NoError(t, sourceErr)
			require.True(t, owned)
			require.Equal(t, "data/object", key)
		})
	}
}

func TestGCOwnershipS3TransitiveAliases(t *testing.T) {
	t.Parallel()
	stores := map[string]config.AdapterConfig{
		"native": s3OwnershipStorage("https://s3.us-east-1.amazonaws.com", ""),
		"bridge": s3OwnershipStorage("https://objects.example", "https://s3.us-east-1.amazonaws.com"),
		"leaf":   s3OwnershipStorage("https://objects.example", "https://edge.example"),
		"edge":   s3OwnershipStorage("https://edge.example", ""),
	}
	orders := [][]string{{"native", "bridge", "leaf", "edge"}, {"edge", "leaf", "bridge", "native"}}
	var fingerprint string
	repo := &Repository{StorageID: "native", StorageNamespace: "s3://bucket/repo"}
	for _, order := range orders {
		c := &Catalog{ownership: newStorageOwnership(orderedGCOwnershipConfig{ownershipTestConfig{stores: stores}, order})}
		if fingerprint == "" {
			fingerprint = c.GCOwnershipFingerprint()
		}
		require.Equal(t, fingerprint, c.GCOwnershipFingerprint())
		for _, id := range order {
			descriptor, err := c.GCTargetDescriptor(&Repository{StorageID: id, StorageNamespace: repo.StorageNamespace})
			require.NoError(t, err)
			require.Equal(t, "aws", descriptor.Service)
			require.Equal(t, []string{"aws", "https://edge.example", "https://objects.example", "https://s3.us-east-1.amazonaws.com"}, descriptor.Routes)
			key, owned, err := c.GCOwnedRelativeAddress(repo, id, "s3://bucket/repo/data/object")
			require.NoError(t, err)
			require.True(t, owned)
			require.Equal(t, "data/object", key)
		}
	}
}

func TestGCOwnershipS3CredentialsAndSeparateServices(t *testing.T) {
	t.Parallel()
	stores := map[string]config.AdapterConfig{
		"owner":     s3OwnershipStorage("https://objects.example", ""),
		"same":      s3OwnershipStorage("https://objects.example", ""),
		"different": s3OwnershipStorage("https://other.example", ""),
	}
	for id, store := range stores {
		store.(*config.BlockstoreStorage).S3.Credentials = &struct {
			AccessKeyID     config.SecureString `mapstructure:"access_key_id"`
			SecretAccessKey config.SecureString `mapstructure:"secret_access_key"`
			SessionToken    config.SecureString `mapstructure:"session_token"`
		}{AccessKeyID: config.SecureString("test-access-" + id), SecretAccessKey: config.SecureString("test-secret-" + id)}
	}
	c := &Catalog{ownership: newStorageOwnership(ownershipTestConfig{stores: stores})}
	repo := &Repository{StorageID: "owner", StorageNamespace: "s3://bucket/repo"}
	for _, source := range []string{"", "owner", "same", "different"} {
		key, owned, err := c.GCOwnedRelativeAddress(repo, source, "s3://bucket/repo/data/object")
		require.NoError(t, err)
		if source == "different" {
			require.False(t, owned)
			require.Empty(t, key)
		} else {
			require.True(t, owned)
			require.Equal(t, "data/object", key)
		}
	}
}

func TestGCOwnershipUnknownAlias(t *testing.T) {
	t.Parallel()
	ownership := storageOwnership{
		"home":  {provider: "s3", service: "https://objects.example", routes: []string{"https://objects.example"}},
		"alias": {provider: "s3", service: "https://objects.example", routes: []string{"https://alias.example"}, gcUnknown: true},
	}
	ownership.collectGCRoutes()
	for id := range ownership {
		_, err := ownership.gcKnownService(id)
		require.ErrorIs(t, err, ErrUnknownStorageOwnership)
	}
}
