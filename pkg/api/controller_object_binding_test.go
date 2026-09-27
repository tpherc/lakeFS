package api_test

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/swag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/config"
)

func setupObjectBindingsClient(t *testing.T, stores []map[string]any) (apigen.ClientWithResponsesInterface, *dependencies) {
	t.Helper()
	viper.Set("blockstores.signing.secret_key", "test-signing-key")
	viper.Set("blockstores.stores", stores)
	t.Cleanup(func() {
		viper.Set("blockstores.stores", nil)
		viper.Set("blockstores.signing.secret_key", nil)
		viper.Set(config.BlockstoreTypeKey, nil)
	})
	handler, deps := setupHandler(t)
	server := setupServer(t, handler)
	client := setupClientByEndpoint(t, server.URL, "", "")
	creds := createDefaultAdminUser(t, client)
	return setupClientByEndpoint(t, server.URL, creds.AccessKeyID, creds.SecretAccessKey), deps
}

func memoryBindingStores() []map[string]any {
	return []map[string]any{
		{"id": "home", "type": "mem", "backward_compatible": true},
		{"id": "source", "type": "mem"},
	}
}

func linkBoundObject(t *testing.T, client apigen.ClientWithResponsesInterface, repo, path, address, storageID string) *apigen.LinkPhysicalAddressResponse {
	t.Helper()
	response, err := client.LinkPhysicalAddressWithResponse(t.Context(), repo, "main", &apigen.LinkPhysicalAddressParams{Path: path}, apigen.LinkPhysicalAddressJSONRequestBody{
		Checksum: "same-etag", SizeBytes: 4,
		Staging: apigen.StagingLocation{PhysicalAddress: &address, StorageId: &storageID},
	})
	require.NoError(t, err)
	return response
}

func TestControllerObjectBindings(t *testing.T) {
	client, deps := setupObjectBindingsClient(t, memoryBindingStores())
	ctx := t.Context()
	repo, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "home", "mem://bucket/repo", "main", false)
	require.NoError(t, err)
	address := "mem://shared/object"
	for id, content := range map[string]string{"home": "AAAA", "source": "BBBB"} {
		_, err := deps.blocks.Put(ctx, block.ObjectPointer{StorageID: id, Identifier: address, IdentifierType: block.IdentifierTypeFull}, 4, strings.NewReader(content), block.PutOpts{})
		require.NoError(t, err)
	}
	for _, id := range []string{"home", "source"} {
		response := linkBoundObject(t, client, repo.Name, "object", address, id)
		require.Equal(t, http.StatusOK, response.StatusCode(), string(response.Body))
		require.Equal(t, id, swag.StringValue(response.JSON200.StorageId))
		commit, err := client.CommitWithResponse(ctx, repo.Name, "main", &apigen.CommitParams{}, apigen.CommitJSONRequestBody{Message: id})
		verifyResponseOK(t, commit, err)
		entry, err := deps.catalog.GetEntry(ctx, repo.Name, commit.JSON201.Id, "object", catalog.GetEntryParams{})
		require.NoError(t, err)
		require.Equal(t, id, entry.StorageID)
		stat, err := client.StatObjectWithResponse(ctx, repo.Name, commit.JSON201.Id, &apigen.StatObjectParams{Path: "object"})
		verifyResponseOK(t, stat, err)
		require.Equal(t, address, stat.JSON200.PhysicalAddress)
		require.Equal(t, id, swag.StringValue(stat.JSON200.StorageId))
		get, err := client.GetObjectWithResponse(ctx, repo.Name, commit.JSON201.Id, &apigen.GetObjectParams{Path: "object"})
		verifyResponseOK(t, get, err)
		expected := "AAAA"
		if id == "source" {
			expected = "BBBB"
		}
		require.Equal(t, expected, string(get.Body))
		ranged, err := client.GetObjectWithResponse(ctx, repo.Name, "main", &apigen.GetObjectParams{Path: "object", Range: swag.String("bytes=1-2")})
		require.NoError(t, err)
		require.Equal(t, http.StatusPartialContent, ranged.StatusCode())
		require.Equal(t, expected[1:3], string(ranged.Body))
	}
	metadata, err := client.UpdateObjectUserMetadataWithResponse(ctx, repo.Name, "main", &apigen.UpdateObjectUserMetadataParams{Path: "object"}, apigen.UpdateObjectUserMetadataJSONRequestBody{
		Set: apigen.ObjectUserMetadata{AdditionalProperties: map[string]string{"review": "kept"}},
	})
	verifyResponseOK(t, metadata, err)
	entry, err := deps.catalog.GetEntry(ctx, repo.Name, "main", "object", catalog.GetEntryParams{})
	require.NoError(t, err)
	require.Equal(t, "source", entry.StorageID)
	copyResult, err := client.CopyObjectWithResponse(ctx, repo.Name, "main", &apigen.CopyObjectParams{DestPath: "physical-copy"}, apigen.CopyObjectJSONRequestBody{SrcPath: "object"})
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, copyResult.StatusCode())
	require.Contains(t, string(copyResult.Body), "cross-storage copy")
	deleted, err := client.DeleteObjectWithResponse(ctx, repo.Name, "main", &apigen.DeleteObjectParams{Path: "object"})
	verifyResponseOK(t, deleted, err)
	exists, err := deps.blocks.Exists(ctx, block.ObjectPointer{StorageID: "source", Identifier: address, IdentifierType: block.IdentifierTypeFull})
	require.NoError(t, err)
	require.True(t, exists)
}

func TestControllerHomeBindingRoundTrip(t *testing.T) {
	client, deps := setupObjectBindingsClient(t, memoryBindingStores())
	repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "home", "mem://bucket/repo", "main", false)
	require.NoError(t, err)
	allocation, err := client.GetPhysicalAddressWithResponse(t.Context(), repo.Name, "main", &apigen.GetPhysicalAddressParams{Path: "allocated"})
	verifyResponseOK(t, allocation, err)
	require.Equal(t, "home", swag.StringValue(allocation.JSON200.StorageId))
	response := linkBoundObject(t, client, repo.Name, "allocated", swag.StringValue(allocation.JSON200.PhysicalAddress), "home")
	require.Equal(t, http.StatusOK, response.StatusCode(), string(response.Body))
	entry, err := deps.catalog.GetEntry(t.Context(), repo.Name, "main", "allocated", catalog.GetEntryParams{})
	require.NoError(t, err)
	require.Empty(t, entry.StorageID)
	require.Equal(t, catalog.AddressTypeRelative, entry.AddressType)
	// Same URI text on a distinct backend must remain FULL, without a home signature.
	address := repo.StorageNamespace + "/data/unsigned"
	foreign := linkBoundObject(t, client, repo.Name, "foreign", address, "source")
	require.Equal(t, http.StatusOK, foreign.StatusCode(), string(foreign.Body))
	entry, err = deps.catalog.GetEntry(t.Context(), repo.Name, "main", "foreign", catalog.GetEntryParams{})
	require.NoError(t, err)
	require.Equal(t, "source", entry.StorageID)
	require.Equal(t, catalog.AddressTypeFull, entry.AddressType)
	rejected := linkBoundObject(t, client, repo.Name, "unsigned-home", address, "home")
	require.Equal(t, http.StatusBadRequest, rejected.StatusCode())
	stage, err := client.StageObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StageObjectParams{Path: "staged-home"}, apigen.StageObjectJSONRequestBody{
		PhysicalAddress: address, StorageId: swag.String("home"), Checksum: "etag", SizeBytes: 4,
	})
	verifyResponseOK(t, stage, err)
	entry, err = deps.catalog.GetEntry(t.Context(), repo.Name, "main", "staged-home", catalog.GetEntryParams{})
	require.NoError(t, err)
	require.Empty(t, entry.StorageID)
	require.Equal(t, catalog.AddressTypeRelative, entry.AddressType)
	unknown := linkBoundObject(t, client, repo.Name, "unknown", address, "missing")
	require.Equal(t, http.StatusNotFound, unknown.StatusCode())
	invalidStage, err := client.StageObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StageObjectParams{Path: "unknown"}, apigen.StageObjectJSONRequestBody{
		PhysicalAddress: address, StorageId: swag.String("missing"), Checksum: "etag", SizeBytes: 4,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, invalidStage.StatusCode())
}

func TestControllerBindingMetadataWithoutSourceConfiguration(t *testing.T) {
	client, deps := setupObjectBindingsClient(t, memoryBindingStores())
	repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "home", "mem://bucket/repo", "main", false)
	require.NoError(t, err)
	entry := catalog.NewDBEntryBuilder().Path("dir/object").PhysicalAddress("gs://source/a//b%2Fc").AddressType(catalog.AddressTypeFull).StorageID("removed").CreationDate(time.Now()).Checksum("etag").Size(4).Build()
	require.NoError(t, deps.catalog.CreateEntry(t.Context(), repo.Name, "main", entry))
	stat, err := client.StatObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StatObjectParams{Path: entry.Path})
	verifyResponseOK(t, stat, err)
	require.Equal(t, "removed", swag.StringValue(stat.JSON200.StorageId))
	require.Equal(t, entry.PhysicalAddress, stat.JSON200.PhysicalAddress)
	listing, err := client.ListObjectsWithResponse(t.Context(), repo.Name, "main", &apigen.ListObjectsParams{})
	verifyResponseOK(t, listing, err)
	require.Equal(t, "removed", swag.StringValue(listing.JSON200.Results[0].StorageId))
	prefixes, err := client.ListObjectsWithResponse(t.Context(), repo.Name, "main", &apigen.ListObjectsParams{Delimiter: (*apigen.PaginationDelimiter)(swag.String("/"))})
	verifyResponseOK(t, prefixes, err)
	require.Nil(t, prefixes.JSON200.Results[0].StorageId)
	get, err := client.GetObjectWithResponse(t.Context(), repo.Name, "main", &apigen.GetObjectParams{Path: entry.Path})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, get.StatusCode())
	presign, err := client.StatObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StatObjectParams{Path: entry.Path, Presign: swag.Bool(true)})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, presign.StatusCode())
}

func TestControllerSymlinkRejectsBeforePublishing(t *testing.T) {
	client, deps := setupObjectBindingsClient(t, memoryBindingStores())
	repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "home", "mem://bucket/repo", "main", false)
	require.NoError(t, err)
	for _, path := range []string{"a/object", "b/object", "z/unsupported"} {
		id := "home"
		if strings.HasPrefix(path, "z/") {
			id = "source"
		}
		response := linkBoundObject(t, client, repo.Name, path, "mem://external/"+path, id)
		require.Equal(t, http.StatusOK, response.StatusCode(), string(response.Body))
	}
	export, err := client.CreateSymlinkFileWithResponse(t.Context(), repo.Name, "main", &apigen.CreateSymlinkFileParams{})
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, export.StatusCode())
	for _, directory := range []string{"a", "b", "z"} {
		exists, err := deps.blocks.Exists(t.Context(), block.ObjectPointer{StorageID: "home", StorageNamespace: repo.StorageNamespace, IdentifierType: block.IdentifierTypeRelative, Identifier: "symlinks/" + repo.Name + "/main/" + directory + "/symlink.txt"})
		require.NoError(t, err)
		require.False(t, exists, "export must publish nothing before all bindings are validated")
	}
}

func TestControllerBindingDumpRestoreRelocation(t *testing.T) {
	client, deps := setupObjectBindingsClient(t, memoryBindingStores())
	ctx := t.Context()
	repo, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "home", "mem://bucket/original", "main", false)
	require.NoError(t, err)
	entries := []catalog.DBEntry{
		catalog.NewDBEntryBuilder().Path("managed").PhysicalAddress("data/managed").AddressType(catalog.AddressTypeRelative).CreationDate(time.Now()).Checksum("etag").Size(4).Build(),
		catalog.NewDBEntryBuilder().Path("external").PhysicalAddress("mem://shared/external").AddressType(catalog.AddressTypeFull).StorageID("source").CreationDate(time.Now()).Checksum("etag").Size(4).Build(),
	}
	for _, entry := range entries {
		pointer, err := block.NewObjectPointer(entry.StorageID, repo.StorageID, repo.StorageNamespace, entry.PhysicalAddress, entry.AddressType.ToIdentifierType())
		require.NoError(t, err)
		_, err = deps.blocks.Put(ctx, pointer, 4, strings.NewReader("data"), block.PutOpts{})
		require.NoError(t, err)
		require.NoError(t, deps.catalog.CreateEntry(ctx, repo.Name, "main", entry))
	}
	commit, err := client.CommitWithResponse(ctx, repo.Name, "main", &apigen.CommitParams{}, apigen.CommitJSONRequestBody{Message: "mixed bindings"})
	verifyResponseOK(t, commit, err)
	dump, err := client.DumpSubmitWithResponse(ctx, repo.Name)
	verifyResponseOK(t, dump, err)
	var status *apigen.RepositoryDumpStatus
	require.Eventually(t, func() bool {
		response, err := client.DumpStatusWithResponse(ctx, repo.Name, &apigen.DumpStatusParams{TaskId: dump.JSON202.Id})
		verifyResponseOK(t, response, err)
		status = response.JSON200
		return status.Done
	}, 10*time.Second, 10*time.Millisecond)
	require.Nil(t, status.Error)
	require.NotNil(t, status.Refs)

	// Restore needs both committed metadata and home-managed data relocated.
	namespace := "mem://bucket/relocated"
	uri, err := url.Parse(repo.StorageNamespace)
	require.NoError(t, err)
	walker, err := deps.blocks.GetWalker(repo.StorageID, block.WalkerOptions{StorageURI: uri})
	require.NoError(t, err)
	var addresses []string
	err = walker.Walk(ctx, uri, block.WalkOptions{}, func(entry block.ObjectStoreEntry) error {
		addresses = append(addresses, entry.Address)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, addresses)
	for _, address := range addresses {
		reader, err := deps.blocks.Get(ctx, block.ObjectPointer{StorageID: repo.StorageID, Identifier: address, IdentifierType: block.IdentifierTypeFull})
		require.NoError(t, err)
		content, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		require.NoError(t, readErr)
		require.NoError(t, closeErr)
		_, err = deps.blocks.Put(ctx, block.ObjectPointer{
			StorageID: "source", Identifier: strings.Replace(address, repo.StorageNamespace, namespace, 1), IdentifierType: block.IdentifierTypeFull,
		}, int64(len(content)), strings.NewReader(string(content)), block.PutOpts{})
		require.NoError(t, err)
	}
	restored, err := deps.catalog.CreateBareRepository(ctx, testUniqueRepoName(), "source", namespace, "main", false)
	require.NoError(t, err)
	submit, err := client.RestoreSubmitWithResponse(ctx, restored.Name, apigen.RestoreSubmitJSONRequestBody{
		BranchesMetaRangeId: status.Refs.BranchesMetaRangeId,
		CommitsMetaRangeId:  status.Refs.CommitsMetaRangeId,
		TagsMetaRangeId:     status.Refs.TagsMetaRangeId,
	})
	verifyResponseOK(t, submit, err)
	restoreStatus := pollRestoreStatus(t, client, restored.Name, submit.JSON202.Id)
	require.NotNil(t, restoreStatus)
	require.Nil(t, restoreStatus.Error)
	for _, expected := range entries {
		entry, err := deps.catalog.GetEntry(ctx, restored.Name, "main", expected.Path, catalog.GetEntryParams{})
		require.NoError(t, err)
		require.Equal(t, expected.StorageID, entry.StorageID)
		require.Equal(t, expected.AddressType, entry.AddressType)
		require.Equal(t, expected.PhysicalAddress, entry.PhysicalAddress)
		get, err := client.GetObjectWithResponse(ctx, restored.Name, "main", &apigen.GetObjectParams{Path: expected.Path})
		verifyResponseOK(t, get, err)
		require.Equal(t, "data", string(get.Body))
	}
}

func TestControllerImportBindingsAndPagination(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for directory, content := range map[string]string{first: "AAAA", second: "BBBB"} {
		require.NoError(t, os.WriteFile(filepath.Join(directory, "object"), []byte(content), 0o600))
	}
	client, deps := setupObjectBindingsClient(t, []map[string]any{
		{"id": "home", "type": "mem", "backward_compatible": true},
		{"id": "first", "type": "local", "local": map[string]any{"path": first, "import_enabled": true}},
		{"id": "second", "type": "local", "local": map[string]any{"path": second, "import_enabled": true}},
	})
	ctx := t.Context()
	repo, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "home", "mem://bucket/repo", "main", false)
	require.NoError(t, err)
	// Import must use each source's capability even though home does not support import.
	started, err := client.ImportStartWithResponse(ctx, repo.Name, "main", apigen.ImportStartJSONRequestBody{
		Commit: apigen.CommitCreation{Message: "two source backends"},
		Paths: []apigen.ImportLocation{
			{Type: "common_prefix", Path: "local://" + first + "/", Destination: "first", StorageId: swag.String("first")},
			{Type: "object", Path: "local://" + second + "/object", Destination: "second", StorageId: swag.String("second")},
		},
	})
	verifyResponseOK(t, started, err)
	var status *apigen.ImportStatus
	require.Eventually(t, func() bool {
		response, err := client.ImportStatusWithResponse(ctx, repo.Name, "main", &apigen.ImportStatusParams{Id: started.JSON202.Id})
		verifyResponseOK(t, response, err)
		status = response.JSON200
		return status.Completed || status.Error != nil
	}, 10*time.Second, 10*time.Millisecond)
	require.Nil(t, status.Error)
	require.NotNil(t, status.Commit)
	amount := apigen.PaginationAmount(1)
	after := apigen.PaginationAfter("")
	for _, expected := range []struct{ path, id, address, content string }{
		{"first/object", "first", "local://" + first + "/object", "AAAA"},
		{"second", "second", "local://" + second + "/object", "BBBB"},
	} {
		listing, err := client.ListObjectsWithResponse(ctx, repo.Name, status.Commit.Id, &apigen.ListObjectsParams{Amount: &amount, After: &after})
		verifyResponseOK(t, listing, err)
		require.Len(t, listing.JSON200.Results, 1)
		entry := listing.JSON200.Results[0]
		require.Equal(t, expected.path, entry.Path)
		require.Equal(t, expected.id, swag.StringValue(entry.StorageId))
		require.Equal(t, expected.address, entry.PhysicalAddress)
		after = apigen.PaginationAfter(entry.Path)
		stored, err := deps.catalog.GetEntry(ctx, repo.Name, status.Commit.Id, entry.Path, catalog.GetEntryParams{})
		require.NoError(t, err)
		require.Equal(t, catalog.AddressTypeFull, stored.AddressType)
		require.Equal(t, expected.id, stored.StorageID)
		read, err := client.GetObjectWithResponse(ctx, repo.Name, status.Commit.Id, &apigen.GetObjectParams{Path: entry.Path})
		verifyResponseOK(t, read, err)
		require.Equal(t, expected.content, string(read.Body))
	}
}

func TestControllerLocalRelativeAddressFormatting(t *testing.T) {
	client, deps := setupObjectBindingsClient(t, []map[string]any{
		{"id": "home", "type": "local", "backward_compatible": true, "local": map[string]any{"path": t.TempDir()}},
	})
	ctx := t.Context()
	repo, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "home", "local://bucket/repo", "main", false)
	require.NoError(t, err)
	upload, err := uploadObjectHelper(t, ctx, client, "dir/object", strings.NewReader("data"), repo.Name, "main")
	verifyResponseOK(t, upload, err)
	expected := upload.JSON201.PhysicalAddress
	require.True(t, strings.HasPrefix(expected, "local:///"), expected)
	stat, err := client.StatObjectWithResponse(ctx, repo.Name, "main", &apigen.StatObjectParams{Path: "dir/object"})
	verifyResponseOK(t, stat, err)
	require.Equal(t, expected, stat.JSON200.PhysicalAddress)
	listing, err := client.ListObjectsWithResponse(ctx, repo.Name, "main", &apigen.ListObjectsParams{})
	verifyResponseOK(t, listing, err)
	require.Len(t, listing.JSON200.Results, 1)
	require.Equal(t, expected, listing.JSON200.Results[0].PhysicalAddress)
	export, err := client.CreateSymlinkFileWithResponse(ctx, repo.Name, "main", &apigen.CreateSymlinkFileParams{})
	verifyResponseOK(t, export, err)
	manifest, err := deps.blocks.Get(ctx, block.ObjectPointer{
		StorageID: "home", StorageNamespace: repo.StorageNamespace, IdentifierType: block.IdentifierTypeRelative,
		Identifier: "symlinks/" + repo.Name + "/main/dir/symlink.txt",
	})
	require.NoError(t, err)
	defer manifest.Close()
	content, err := io.ReadAll(manifest)
	require.NoError(t, err)
	require.Equal(t, expected, string(content))
}
