package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-openapi/swag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestControllerLegacyStoreRejectsUnavailableBinding(t *testing.T) {
	endpoint, calls := newBindingS3Endpoint(t, "legacy-access-key", "HOME", "STANDARD")
	store := bindingS3Store("", endpoint.URL, "legacy-access-key", false)
	viper.Set(config.BlockstoreTypeKey, "s3")
	viper.Set("blockstore.s3", store["s3"])
	t.Cleanup(func() {
		viper.Set(config.BlockstoreTypeKey, nil)
		viper.Set("blockstore.s3", nil)
	})
	client, deps := setupClientWithAdmin(t)
	ctx := t.Context()
	repo, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "", "s3://shared/repo", "main", false)
	require.NoError(t, err)
	const address = "s3://shared/raw/object"
	for path, id := range map[string]string{"legacy": "", "restored": "unavailable-source"} {
		entry := catalog.NewDBEntryBuilder().Path(path).PhysicalAddress(address).AddressType(catalog.AddressTypeFull).
			StorageID(id).CreationDate(time.Now()).Checksum("same-etag").Size(4).Build()
		require.NoError(t, deps.catalog.CreateEntry(ctx, repo.Name, "main", entry))
	}
	stat, err := client.StatObjectWithResponse(ctx, repo.Name, "main", &apigen.StatObjectParams{Path: "restored"})
	verifyResponseOK(t, stat, err)
	require.Equal(t, "unavailable-source", swag.StringValue(stat.JSON200.StorageId))
	require.Equal(t, address, stat.JSON200.PhysicalAddress)
	listing, err := client.ListObjectsWithResponse(ctx, repo.Name, "main", &apigen.ListObjectsParams{})
	verifyResponseOK(t, listing, err)
	require.Len(t, listing.JSON200.Results, 2)

	for _, byteRange := range []*string{nil, swag.String("bytes=1-2")} {
		read, err := client.GetObjectWithResponse(ctx, repo.Name, "main", &apigen.GetObjectParams{Path: "restored", Range: byteRange})
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, read.StatusCode(), string(read.Body))
	}
	signed, err := client.StatObjectWithResponse(ctx, repo.Name, "main", &apigen.StatObjectParams{Path: "restored", Presign: swag.Bool(true)})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, signed.StatusCode(), string(signed.Body))
	properties, err := client.GetUnderlyingPropertiesWithResponse(ctx, repo.Name, "main", &apigen.GetUnderlyingPropertiesParams{Path: "restored"})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, properties.StatusCode(), string(properties.Body))
	copied, err := client.CopyObjectWithResponse(ctx, repo.Name, "main", &apigen.CopyObjectParams{DestPath: "copy"}, apigen.CopyObjectJSONRequestBody{SrcPath: "restored"})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, copied.StatusCode(), string(copied.Body))
	require.Zero(t, calls.Load(), "unavailable bindings must never reach the sole backend")

	legacy, err := client.GetObjectWithResponse(ctx, repo.Name, "main", &apigen.GetObjectParams{Path: "legacy"})
	verifyResponseOK(t, legacy, err)
	require.Equal(t, "HOME", string(legacy.Body))
	legacySigned, err := client.StatObjectWithResponse(ctx, repo.Name, "main", &apigen.StatObjectParams{Path: "legacy", Presign: swag.Bool(true)})
	verifyResponseOK(t, legacySigned, err)
	require.True(t, strings.HasPrefix(legacySigned.JSON200.PhysicalAddress, endpoint.URL+"/shared/raw/object?"))
}

func TestControllerAzureFullLocatorCannotInheritNamespace(t *testing.T) {
	var calls atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("ETag", `"same-etag"`)
		w.Header().Set("Last-Modified", "Sat, 26 Sep 2026 00:00:00 GMT")
		w.Header().Set("x-ms-blob-type", "BlockBlob")
		w.Header().Set("Content-Length", "4")
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "data")
		}
	}))
	t.Cleanup(endpoint.Close)
	store := func(id string, compatible bool) map[string]any {
		return map[string]any{"id": id, "type": "azure", "backward_compatible": compatible, "azure": map[string]any{
			"storage_account": "account", "storage_access_key": "dGVzdC1vbmx5LWFjY291bnQta2V5", "test_endpoint_url": endpoint.URL,
		}}
	}
	client, deps := setupObjectBindingsClient(t, []map[string]any{store("home", true), store("source", false)})
	ctx := t.Context()
	repo, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "home", "https://account.blob.core.windows.net/container/repo", "main", false)
	require.NoError(t, err)
	for _, id := range []string{"home", "source"} {
		linked := linkBoundObject(t, client, repo.Name, id, "data/x", id)
		require.Equal(t, http.StatusOK, linked.StatusCode(), string(linked.Body))
		stat, err := client.StatObjectWithResponse(ctx, repo.Name, "main", &apigen.StatObjectParams{Path: id})
		verifyResponseOK(t, stat, err)
		require.Equal(t, "data/x", stat.JSON200.PhysicalAddress)
		read, err := client.GetObjectWithResponse(ctx, repo.Name, "main", &apigen.GetObjectParams{Path: id})
		require.NoError(t, err)
		require.GreaterOrEqual(t, read.StatusCode(), http.StatusBadRequest, string(read.Body))
		signed, err := client.StatObjectWithResponse(ctx, repo.Name, "main", &apigen.StatObjectParams{Path: id, Presign: swag.Bool(true)})
		require.NoError(t, err)
		require.GreaterOrEqual(t, signed.StatusCode(), http.StatusBadRequest, string(signed.Body))
	}
	require.Zero(t, calls.Load(), "opaque FULL locators must not borrow home account/container context")
	linked := linkBoundObject(t, client, repo.Name, "valid", "https://account.blob.core.windows.net/container/external", "source")
	require.Equal(t, http.StatusOK, linked.StatusCode(), string(linked.Body))
	read, err := client.GetObjectWithResponse(ctx, repo.Name, "main", &apigen.GetObjectParams{Path: "valid"})
	verifyResponseOK(t, read, err)
	require.Equal(t, "data", string(read.Body))
	require.Equal(t, int64(1), calls.Load())
}

func TestControllerS3ManagedAliasesRequireSignature(t *testing.T) {
	internal, internalCalls := newBindingS3Endpoint(t, "home-key", "HOME", "STANDARD")
	external, externalCalls := newBindingS3Endpoint(t, "alias-key", "HOME", "STANDARD")
	home := bindingS3Store("home", internal.URL, "home-key", true)
	home["s3"].(map[string]any)["pre_signed_endpoint"] = external.URL
	client, deps := setupObjectBindingsClient(t, []map[string]any{home, bindingS3Store("alias", external.URL, "alias-key", false)})
	ctx := t.Context()
	repo, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "home", "s3://shared/repo", "main", false)
	require.NoError(t, err)
	for _, tc := range []struct{ id, scheme string }{
		{"alias", "s3"}, {"alias", "gs"}, {"home", "gs"},
	} {
		t.Run(tc.id+"/"+tc.scheme, func(t *testing.T) {
			path := tc.id + "-" + tc.scheme
			unsigned := linkBoundObject(t, client, repo.Name, path, tc.scheme+"://shared/repo/data/unsigned", tc.id)
			require.Equal(t, http.StatusBadRequest, unsigned.StatusCode(), string(unsigned.Body))
			allocated, err := client.GetPhysicalAddressWithResponse(ctx, repo.Name, "main", &apigen.GetPhysicalAddressParams{Path: path})
			verifyResponseOK(t, allocated, err)
			address := strings.Replace(swag.StringValue(allocated.JSON200.PhysicalAddress), "s3://", tc.scheme+"://", 1)
			linked := linkBoundObject(t, client, repo.Name, path, address, tc.id)
			require.Equal(t, http.StatusOK, linked.StatusCode(), string(linked.Body))
			entry, err := deps.catalog.GetEntry(ctx, repo.Name, "main", path, catalog.GetEntryParams{})
			require.NoError(t, err)
			require.Equal(t, tc.id, entry.StorageID)
			require.Equal(t, catalog.AddressTypeFull, entry.AddressType)
			require.Equal(t, address, entry.PhysicalAddress)
		})
	}
	require.Zero(t, internalCalls.Load()+externalCalls.Load(), "managed signature checks are local metadata checks")
}
