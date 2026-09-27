package api_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
)

// These fixtures exercise the native HTTP adapters, not provider-side signature validation.
func newBindingS3Endpoint(t *testing.T, accessKey, content, storageClass string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	calls := new(atomic.Int64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		credential := r.Header.Get("Authorization")
		if credential == "" {
			credential = r.URL.Query().Get("X-Amz-Credential")
		}
		if !strings.Contains(credential, accessKey+"/") {
			http.Error(w, "wrong configured credentials", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/shared/raw/object" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("ETag", `"same-etag"`)
		w.Header().Set("Last-Modified", "Sat, 26 Sep 2026 00:00:00 GMT")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("x-amz-storage-class", storageClass)
		body := content
		status := http.StatusOK
		if r.Header.Get("Range") == "bytes=1-2" {
			body = content[1:3]
			status = http.StatusPartialContent
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 1-2/%d", len(content)))
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, body)
		}
	}))
	t.Cleanup(server.Close)
	return server, calls
}

func bindingS3Store(id, endpoint, accessKey string, compatible bool) map[string]any {
	return map[string]any{
		"id": id, "type": "s3", "backward_compatible": compatible,
		"s3": map[string]any{
			"endpoint": endpoint, "region": "us-east-1", "force_path_style": true,
			"discover_bucket_region": false,
			"credentials":            map[string]any{"access_key_id": accessKey, "secret_access_key": "test-only-secret"},
		},
	}
}

func TestControllerNativeS3Bindings(t *testing.T) {
	first, firstCalls := newBindingS3Endpoint(t, "first-access-key", "AAAA", "STANDARD")
	second, secondCalls := newBindingS3Endpoint(t, "second-access-key", "BBBB", "STANDARD_IA")
	client, deps := setupObjectBindingsClient(t, []map[string]any{
		bindingS3Store("home", first.URL, "first-access-key", true),
		bindingS3Store("source", second.URL, "second-access-key", false),
	})
	repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "home", "s3://shared/repo", "main", false)
	require.NoError(t, err)
	for _, tc := range []struct {
		id, endpoint, accessKey, content, storageClass string
	}{
		{"home", first.URL, "first-access-key", "AAAA", "STANDARD"},
		{"source", second.URL, "second-access-key", "BBBB", "STANDARD_IA"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			before := firstCalls.Load() + secondCalls.Load()
			linked := linkBoundObject(t, client, repo.Name, tc.id, "s3://shared/raw/object", tc.id)
			require.Equal(t, http.StatusOK, linked.StatusCode(), string(linked.Body))
			stat, err := client.StatObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StatObjectParams{Path: tc.id})
			verifyResponseOK(t, stat, err)
			require.Equal(t, tc.id, swag.StringValue(stat.JSON200.StorageId))
			require.Equal(t, "s3://shared/raw/object", stat.JSON200.PhysicalAddress)
			require.Equal(t, before, firstCalls.Load()+secondCalls.Load(), "link and catalog stat must not access storage")

			get, err := client.GetObjectWithResponse(t.Context(), repo.Name, "main", &apigen.GetObjectParams{Path: tc.id})
			verifyResponseOK(t, get, err)
			require.Equal(t, tc.content, string(get.Body))
			ranged, err := client.GetObjectWithResponse(t.Context(), repo.Name, "main", &apigen.GetObjectParams{Path: tc.id, Range: swag.String("bytes=1-2")})
			require.NoError(t, err)
			require.Equal(t, http.StatusPartialContent, ranged.StatusCode(), string(ranged.Body))
			require.Equal(t, tc.content[1:3], string(ranged.Body))
			properties, err := client.GetUnderlyingPropertiesWithResponse(t.Context(), repo.Name, "main", &apigen.GetUnderlyingPropertiesParams{Path: tc.id})
			verifyResponseOK(t, properties, err)
			require.Equal(t, tc.storageClass, swag.StringValue(properties.JSON200.StorageClass))

			signed, err := client.StatObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StatObjectParams{Path: tc.id, Presign: swag.Bool(true)})
			verifyResponseOK(t, signed, err)
			signedURL, err := url.Parse(signed.JSON200.PhysicalAddress)
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(signedURL.String(), tc.endpoint+"/shared/raw/object?"), signedURL.String())
			require.True(t, strings.HasPrefix(signedURL.Query().Get("X-Amz-Credential"), tc.accessKey+"/"))
			require.NotEmpty(t, signedURL.Query().Get("X-Amz-Signature"))
			downloaded, err := http.Get(signedURL.String())
			require.NoError(t, err)
			defer downloaded.Body.Close()
			body, err := io.ReadAll(downloaded.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, downloaded.StatusCode)
			require.Equal(t, tc.content, string(body))
		})
	}
	allocated, err := client.GetPhysicalAddressWithResponse(t.Context(), repo.Name, "main", &apigen.GetPhysicalAddressParams{Path: "upload", Presign: swag.Bool(true)})
	verifyResponseOK(t, allocated, err)
	require.Equal(t, "home", swag.StringValue(allocated.JSON200.StorageId))
	require.True(t, strings.HasPrefix(swag.StringValue(allocated.JSON200.PresignedUrl), first.URL+"/shared/repo/"))
	require.Equal(t, int64(4), firstCalls.Load())
	require.Equal(t, int64(4), secondCalls.Load())
}

func TestControllerNativeS3GCSReferences(t *testing.T) {
	s3Server, _ := newBindingS3Endpoint(t, "s3-access-key", "SSSS", "STANDARD")
	var gcsPropertyCalls atomic.Int64
	gcsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/v1/b/raw/o/object" && r.URL.Query().Get("alt") != "media" {
			gcsPropertyCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"bucket":"raw","name":"object","size":"4","generation":"1","etag":"same-etag","storageClass":"STANDARD","updated":"2026-09-26T00:00:00Z"}`)
			return
		}
		if r.URL.Path != "/raw/object" && r.URL.Path != "/download/storage/v1/b/raw/o/object" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", `"same-etag"`)
		w.Header().Set("Last-Modified", "Sat, 26 Sep 2026 00:00:00 GMT")
		w.Header().Set("X-Goog-Generation", "1")
		if r.Header.Get("Range") == "bytes=1-2" {
			w.Header().Set("Content-Length", "2")
			w.Header().Set("Content-Range", "bytes 1-2/4")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, "GG")
			return
		}
		w.Header().Set("Content-Length", "4")
		_, _ = io.WriteString(w, "GGGG")
	}))
	t.Cleanup(gcsServer.Close)
	t.Setenv("STORAGE_EMULATOR_HOST", gcsServer.URL)
	client, deps := setupObjectBindingsClient(t, []map[string]any{
		bindingS3Store("s3-home", s3Server.URL, "s3-access-key", true),
		{"id": "gcs-home", "type": "gs", "gs": map[string]any{"disable_pre_signed": true}},
		{"id": "gcs-alias", "type": "gs", "gs": map[string]any{"disable_pre_signed": true}},
	})
	for _, tc := range []struct{ home, namespace, source, address, content string }{
		{"s3-home", "s3://shared/repo", "gcs-home", "gs://raw/object", "GGGG"},
		{"gcs-home", "gs://raw/repo", "s3-home", "s3://shared/raw/object", "SSSS"},
	} {
		t.Run(tc.home, func(t *testing.T) {
			repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), tc.home, tc.namespace, "main", false)
			require.NoError(t, err)
			linked := linkBoundObject(t, client, repo.Name, "foreign", tc.address, tc.source)
			require.Equal(t, http.StatusOK, linked.StatusCode(), string(linked.Body))
			stat, err := client.StatObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StatObjectParams{Path: "foreign"})
			verifyResponseOK(t, stat, err)
			require.Equal(t, tc.source, swag.StringValue(stat.JSON200.StorageId))
			require.Equal(t, tc.address, stat.JSON200.PhysicalAddress)
			get, err := client.GetObjectWithResponse(t.Context(), repo.Name, "main", &apigen.GetObjectParams{Path: "foreign"})
			verifyResponseOK(t, get, err)
			require.Equal(t, tc.content, string(get.Body))
			ranged, err := client.GetObjectWithResponse(t.Context(), repo.Name, "main", &apigen.GetObjectParams{Path: "foreign", Range: swag.String("bytes=1-2")})
			require.NoError(t, err)
			require.Equal(t, http.StatusPartialContent, ranged.StatusCode(), string(ranged.Body))
			require.Equal(t, tc.content[1:3], string(ranged.Body))
			beforeProperties := gcsPropertyCalls.Load()
			properties, err := client.GetUnderlyingPropertiesWithResponse(t.Context(), repo.Name, "main", &apigen.GetUnderlyingPropertiesParams{Path: "foreign"})
			verifyResponseOK(t, properties, err)
			if tc.source == "gcs-home" {
				// The native GCS adapter currently returns no storage class.
				require.Nil(t, properties.JSON200.StorageClass)
				require.Equal(t, beforeProperties+1, gcsPropertyCalls.Load())
			} else {
				require.Equal(t, "STANDARD", swag.StringValue(properties.JSON200.StorageClass))
			}
			signed, err := client.StatObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StatObjectParams{Path: "foreign", Presign: swag.Bool(true)})
			require.NoError(t, err)
			if tc.source == "gcs-home" {
				require.Equal(t, http.StatusBadRequest, signed.StatusCode(), string(signed.Body))
			} else {
				require.Equal(t, http.StatusOK, signed.StatusCode(), string(signed.Body))
				require.True(t, strings.HasPrefix(signed.JSON200.PhysicalAddress, s3Server.URL+"/shared/raw/object?"))
			}
		})
	}
	t.Run("GCS managed aliases require home signature", func(t *testing.T) {
		repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "gcs-home", "gs://raw/managed", "main", false)
		require.NoError(t, err)
		unsigned := linkBoundObject(t, client, repo.Name, "unsigned", repo.StorageNamespace+"/data/unsigned", "gcs-alias")
		require.Equal(t, http.StatusBadRequest, unsigned.StatusCode(), string(unsigned.Body))
		allocation, err := client.GetPhysicalAddressWithResponse(t.Context(), repo.Name, "main", &apigen.GetPhysicalAddressParams{Path: "allocated"})
		verifyResponseOK(t, allocation, err)
		linked := linkBoundObject(t, client, repo.Name, "allocated", swag.StringValue(allocation.JSON200.PhysicalAddress), "gcs-alias")
		require.Equal(t, http.StatusOK, linked.StatusCode(), string(linked.Body))
		require.Equal(t, "gcs-alias", swag.StringValue(linked.JSON200.StorageId))
		require.Equal(t, swag.StringValue(allocation.JSON200.PhysicalAddress), linked.JSON200.PhysicalAddress)
	})
}

func TestControllerNativeAzureReference(t *testing.T) {
	azureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "SharedKey sourceaccount:") && r.URL.Query().Get("sig") == "" {
			http.Error(w, "missing native Azure credentials", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/container/object" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"same-etag"`)
		w.Header().Set("Last-Modified", "Sat, 26 Sep 2026 00:00:00 GMT")
		w.Header().Set("x-ms-access-tier", "Hot")
		w.Header().Set("x-ms-blob-type", "BlockBlob")
		body := "AZUR"
		if r.Header.Get("x-ms-range") == "bytes=1-2" || r.Header.Get("Range") == "bytes=1-2" {
			body = "ZU"
			w.Header().Set("Content-Range", "bytes 1-2/4")
			w.Header().Set("Content-Length", "2")
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", "4")
		}
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, body)
		}
	}))
	t.Cleanup(azureServer.Close)
	client, deps := setupObjectBindingsClient(t, []map[string]any{
		{"id": "home", "type": "mem", "backward_compatible": true},
		{"id": "azure-source", "type": "azure", "azure": map[string]any{
			"storage_account": "sourceaccount", "storage_access_key": "dGVzdC1vbmx5LWFjY291bnQta2V5",
			"test_endpoint_url": azureServer.URL,
		}},
	})
	repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "home", "mem://repo", "main", false)
	require.NoError(t, err)
	const address = "https://sourceaccount.blob.core.windows.net/container/object"
	linked := linkBoundObject(t, client, repo.Name, "foreign", address, "azure-source")
	require.Equal(t, http.StatusOK, linked.StatusCode(), string(linked.Body))
	get, err := client.GetObjectWithResponse(t.Context(), repo.Name, "main", &apigen.GetObjectParams{Path: "foreign"})
	verifyResponseOK(t, get, err)
	require.Equal(t, "AZUR", string(get.Body))
	ranged, err := client.GetObjectWithResponse(t.Context(), repo.Name, "main", &apigen.GetObjectParams{Path: "foreign", Range: swag.String("bytes=1-2")})
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, ranged.StatusCode(), string(ranged.Body))
	require.Equal(t, "ZU", string(ranged.Body))
	properties, err := client.GetUnderlyingPropertiesWithResponse(t.Context(), repo.Name, "main", &apigen.GetUnderlyingPropertiesParams{Path: "foreign"})
	verifyResponseOK(t, properties, err)
	require.Equal(t, "Hot", swag.StringValue(properties.JSON200.StorageClass))
	signed, err := client.StatObjectWithResponse(t.Context(), repo.Name, "main", &apigen.StatObjectParams{Path: "foreign", Presign: swag.Bool(true)})
	verifyResponseOK(t, signed, err)
	require.Equal(t, "azure-source", swag.StringValue(signed.JSON200.StorageId))
	signedURL, err := url.Parse(signed.JSON200.PhysicalAddress)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(signedURL.String(), azureServer.URL+"/container/object?"))
	require.NotEmpty(t, signedURL.Query().Get("sig"))
	require.Equal(t, "r", signedURL.Query().Get("sp"))
}
