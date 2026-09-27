package api_test

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	lakefshttp "github.com/treeverse/lakefs/pkg/httputil"
	"github.com/xitongsys/parquet-go-source/buffer"
	"github.com/xitongsys/parquet-go/reader"
)

// Persist metadata and GC artifacts through the native S3 adapter. This endpoint
// checks selected credentials but does not implement provider signature validation.
func newGCReferencesS3Endpoint(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.RWMutex
	type object struct {
		content  []byte
		modified time.Time
	}
	objects := make(map[string]object)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "gc-access-key/") {
			http.Error(w, "unexpected credentials", http.StatusForbidden)
			return
		}
		bucket := strings.Trim(r.URL.Path, "/")
		isBucket := bucket != "" && !strings.Contains(bucket, "/")
		if isBucket && r.Method == http.MethodHead {
			w.Header().Set("x-amz-bucket-region", "us-east-1")
			w.WriteHeader(http.StatusOK)
			return
		}
		if isBucket && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/xml")
			if r.URL.Query().Has("location") {
				_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
				return
			}
			prefix, delimiter := r.URL.Query().Get("prefix"), r.URL.Query().Get("delimiter")
			after := r.URL.Query().Get("continuation-token")
			if after == "" {
				after = r.URL.Query().Get("marker")
			}
			type item struct {
				Key          string
				LastModified string
				ETag         string
				Size         int
				StorageClass string
			}
			type commonPrefix struct{ Prefix string }
			result := struct {
				XMLName               xml.Name `xml:"ListBucketResult"`
				Name                  string
				Prefix                string
				Delimiter             string
				MaxKeys               int
				KeyCount              int
				IsTruncated           bool
				NextContinuationToken string `xml:",omitempty"`
				NextMarker            string `xml:",omitempty"`
				Contents              []item
				CommonPrefixes        []commonPrefix
			}{Name: bucket, Prefix: prefix, Delimiter: delimiter, MaxKeys: 2}
			if requested, err := strconv.Atoi(r.URL.Query().Get("max-keys")); err == nil && requested > 0 && requested < result.MaxKeys {
				result.MaxKeys = requested
			}
			mu.RLock()
			keys := make([]string, 0)
			for path := range objects {
				key, ok := strings.CutPrefix(path, "/"+bucket+"/")
				if ok && strings.HasPrefix(key, prefix) && key > after {
					keys = append(keys, key)
				}
			}
			sort.Strings(keys)
			seen := make(map[string]bool)
			for index, key := range keys {
				if delimiter != "" && strings.Contains(strings.TrimPrefix(key, prefix), delimiter) {
					part, _, _ := strings.Cut(strings.TrimPrefix(key, prefix), delimiter)
					value := prefix + part + delimiter
					if seen[value] {
						continue
					}
					seen[value] = true
					result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix{value})
				} else {
					object := objects["/"+bucket+"/"+key]
					result.Contents = append(result.Contents, item{key, object.modified.UTC().Format(time.RFC3339), `"` + gcReferencesS3ETag(object.content) + `"`, len(object.content), "STANDARD"})
				}
				result.KeyCount++
				if result.KeyCount == result.MaxKeys && index+1 < len(keys) {
					result.IsTruncated, result.NextContinuationToken, result.NextMarker = true, key, key
					break
				}
			}
			mu.RUnlock()
			_ = xml.NewEncoder(w).Encode(result)
			return
		}
		if isBucket && r.Method == http.MethodPost && r.URL.Query().Has("delete") {
			var request struct {
				Objects []struct{ Key string } `xml:"Object"`
			}
			if err := xml.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			result := struct {
				XMLName xml.Name `xml:"DeleteResult"`
				Deleted []struct{ Key string }
			}{}
			mu.Lock()
			for _, object := range request.Objects {
				delete(objects, "/"+bucket+"/"+object.Key)
				result.Deleted = append(result.Deleted, struct{ Key string }{object.Key})
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			_ = xml.NewEncoder(w).Encode(result)
			return
		}
		if r.Method == http.MethodPut {
			var payload io.Reader = r.Body
			if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") || strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
				// The HTTP server removes transfer framing, but AWS payload framing
				// remains inside the body. Chunk signatures are not verified here.
				payload = httputil.NewChunkedReader(r.Body)
			}
			content, err := io.ReadAll(payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if expected := r.Header.Get("Content-MD5"); expected != "" {
				sum := md5.Sum(content)
				actual := base64.StdEncoding.EncodeToString(sum[:])
				if actual != expected {
					t.Logf("fixture PUT integrity mismatch: encoding=%q sha-kind=%q decoded-length=%q size=%d", r.Header.Get("Content-Encoding"), r.Header.Get("X-Amz-Content-Sha256"), r.Header.Get("X-Amz-Decoded-Content-Length"), len(content))
					http.Error(w, "fixture payload digest mismatch", http.StatusBadRequest)
					return
				}
			}
			modified := time.Now().UTC()
			if requested := r.Header.Get("X-Test-Modified-At"); requested != "" {
				modified, err = time.Parse(time.RFC3339, requested)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			mu.Lock()
			objects[r.URL.Path] = object{content, modified}
			mu.Unlock()
			w.Header().Set("ETag", `"`+gcReferencesS3ETag(content)+`"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		mu.RLock()
		stored, found := objects[r.URL.Path]
		mu.RUnlock()
		content := stored.content
		if !found {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "<Error><Code>NoSuchKey</Code><Message>Object not found</Message></Error>")
			return
		}
		w.Header().Set("ETag", `"`+gcReferencesS3ETag(content)+`"`)
		w.Header().Set("Last-Modified", stored.modified.UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/octet-stream")
		status := http.StatusOK
		if requested := r.Header.Get("Range"); requested != "" {
			rng, err := lakefshttp.ParseRange(requested, int64(len(content)))
			if err != nil {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.StartOffset, rng.EndOffset, len(content)))
			content = content[rng.StartOffset : rng.EndOffset+1]
			status = http.StatusPartialContent
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.WriteHeader(status)
		if r.Method == http.MethodGet {
			_, _ = w.Write(content)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func setupGCReferencesAPI(t *testing.T) (apigen.ClientWithResponsesInterface, *dependencies, *catalog.Repository) {
	t.Helper()
	endpoint := newGCReferencesS3Endpoint(t)
	client, deps := setupObjectBindingsClient(t, []map[string]any{
		bindingS3Store("home", endpoint.URL, "gc-access-key", true),
		{"id": "view-store", "type": "mem"},
	})
	repo, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "home", "s3://gc-bucket/owner", "main", false)
	require.NoError(t, err)
	return client, deps, repo
}

func gcReferencesS3ETag(content []byte) string {
	// S3's SDK verifies a single-part ETag using MD5 independently of our manifest SHA-256.
	sum := md5.Sum(content)
	return hex.EncodeToString(sum[:])
}

func gcReferencesAPIDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func waitGCReferencesAPI(t *testing.T, client apigen.ClientWithResponsesInterface, repository, taskID string) *apigen.PrepareGarbageCollectionReferencesStatus {
	t.Helper()
	var status *apigen.PrepareGarbageCollectionReferencesStatus
	require.Eventually(t, func() bool {
		response, err := client.PrepareGarbageCollectionReferencesStatusWithResponse(t.Context(), repository, &apigen.PrepareGarbageCollectionReferencesStatusParams{Id: taskID})
		verifyResponseOK(t, response, err)
		status = response.JSON200
		return status.Completed
	}, 10*time.Second, 10*time.Millisecond)
	return status
}

func readGCReferencesArtifact(t *testing.T, deps *dependencies, location string) []byte {
	t.Helper()
	content, err := deps.blocks.Get(t.Context(), block.ObjectPointer{StorageID: "home", Identifier: location, IdentifierType: block.IdentifierTypeFull})
	require.NoError(t, err)
	defer func() { require.NoError(t, content.Close()) }()
	data, err := io.ReadAll(content)
	require.NoError(t, err)
	return data
}

type gcReferencesAPIRow struct {
	PhysicalAddress string `parquet:"name=physical_address, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
}

func TestGCReferencesAPIManifest(t *testing.T) {
	for _, crossRepository := range []bool{false, true} {
		name := "empty"
		if crossRepository {
			name = "cross repository committed and staged references"
		}
		t.Run(name, func(t *testing.T) {
			client, deps, owner := setupGCReferencesAPI(t)
			ctx := t.Context()
			var expected []string
			if crossRepository {
				view, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "view-store", "mem://views/repository", "main", false)
				require.NoError(t, err)
				for _, path := range []string{"committed", "staged"} {
					entry := catalog.NewDBEntryBuilder().Path(path).StorageID("home").AddressType(catalog.AddressTypeFull).
						PhysicalAddress(owner.StorageNamespace + "/data/" + path).CreationDate(time.Now()).Checksum("etag").Size(1).Build()
					require.NoError(t, deps.catalog.CreateEntry(ctx, view.Name, "main", entry))
					expected = append(expected, "data/"+path)
					if path == "committed" {
						committed, err := client.CommitWithResponse(ctx, view.Name, "main", &apigen.CommitParams{}, apigen.CommitJSONRequestBody{Message: "retain owner object"})
						verifyResponseOK(t, committed, err)
					}
				}
				// Exercise the existing catalog clone helper; Community HTTP shallow
				// copy support and its restrictions remain unchanged.
				clone, err := deps.catalog.CopyEntry(ctx, view.Name, "main", "staged", view.Name, "main", "shallow-staged", false, nil, func(options *graveler.SetOptions) { options.Shallow = true })
				require.NoError(t, err)
				require.Equal(t, "home", clone.StorageID)
				require.Equal(t, owner.StorageNamespace+"/data/staged", clone.PhysicalAddress)
				deleted, err := client.DeleteObjectWithResponse(ctx, view.Name, "main", &apigen.DeleteObjectParams{Path: "staged"})
				verifyResponseOK(t, deleted, err)
				_, err = deps.catalog.CreateBranch(ctx, view.Name, "hidden", "main", graveler.WithHidden(true))
				require.NoError(t, err)
				hidden := catalog.NewDBEntryBuilder().Path("hidden-reference").StorageID("home").AddressType(catalog.AddressTypeFull).
					PhysicalAddress(owner.StorageNamespace + "/data/hidden").CreationDate(time.Now()).Checksum("etag").Size(1).Build()
				require.NoError(t, deps.catalog.CreateEntry(ctx, view.Name, "hidden", hidden))
				branches, _, err := deps.catalog.ListBranches(ctx, view.Name, "", 10, "")
				require.NoError(t, err)
				require.Len(t, branches, 1, "the protection fixture must include a branch hidden from normal listings")
				expected = append(expected, "data/hidden")
				external := catalog.NewDBEntryBuilder().Path("outside").StorageID("home").AddressType(catalog.AddressTypeFull).
					PhysicalAddress("s3://gc-bucket/ownership/data/object").CreationDate(time.Now()).Checksum("etag").Size(1).Build()
				require.NoError(t, deps.catalog.CreateEntry(ctx, view.Name, "main", external))
			}
			startedBefore := time.Now().UTC()
			started, err := client.PrepareGarbageCollectionReferencesAsyncWithResponse(ctx, owner.Name, apigen.PrepareGarbageCollectionReferencesAsyncJSONRequestBody{})
			require.NoError(t, err)
			require.Equal(t, http.StatusAccepted, started.StatusCode(), string(started.Body))
			require.NotNil(t, started.JSON202)
			status := waitGCReferencesAPI(t, client, owner.Name, started.JSON202.Id)
			require.Nil(t, status.Error)
			require.NotNil(t, status.Result)
			require.Equal(t, started.JSON202.Id, status.TaskId)
			require.Contains(t, status.Result.ManifestLocation, started.JSON202.Id)
			require.True(t, strings.HasPrefix(status.Result.ManifestLocation, owner.StorageNamespace+"/"))
			data := readGCReferencesArtifact(t, deps, status.Result.ManifestLocation)
			require.Equal(t, status.Result.ManifestSha256, gcReferencesAPIDigest(data))
			var manifest catalog.GCReferencesManifest
			require.NoError(t, json.Unmarshal(data, &manifest))
			require.Equal(t, catalog.GCReferencesSchemaVersion, manifest.SchemaVersion)
			require.Equal(t, "installation", manifest.Scope)
			require.Equal(t, status.TaskId, manifest.TaskID)
			require.Equal(t, status.TaskId, manifest.RunID)
			require.Equal(t, owner.Name, manifest.RepositoryID)
			require.NotEmpty(t, manifest.RepositoryInstanceUID)
			require.Equal(t, "home", manifest.StorageID)
			require.Equal(t, owner.StorageNamespace, manifest.StorageNamespace)
			require.Equal(t, deps.catalog.GCOwnershipFingerprint(), manifest.OwnershipFingerprint)
			require.Equal(t, catalog.GCOwnershipResolverVersion, manifest.OwnershipResolverVersion)
			require.Equal(t, int64(86400), manifest.MinimumAgeSeconds)
			require.Equal(t, 24*time.Hour, manifest.StartedAt.Sub(manifest.CutoffTime))
			require.False(t, manifest.StartedAt.Before(startedBefore))
			require.False(t, manifest.CompletedAt.Before(manifest.StartedAt))
			require.Equal(t, status.Result.ExpiresAt, manifest.ExpiresAt)
			require.Equal(t, catalog.GCReferencesLifetime, manifest.ExpiresAt.Sub(manifest.CompletedAt))
			require.Equal(t, "s3", manifest.Target.Provider)
			require.Equal(t, "gc-bucket", manifest.Target.Bucket)
			require.Equal(t, "owner/", manifest.Target.NamespacePrefix)
			var addresses []string
			for _, part := range manifest.Parts {
				partData := readGCReferencesArtifact(t, deps, part.Location)
				require.Equal(t, part.SHA256, gcReferencesAPIDigest(partData))
				require.Equal(t, part.SizeBytes, int64(len(partData)))
				file := buffer.NewBufferFileFromBytes(partData)
				parquet, err := reader.NewParquetReader(file, new(gcReferencesAPIRow), 1)
				require.NoError(t, err)
				require.Equal(t, part.RowCount, parquet.GetNumRows())
				rows := make([]gcReferencesAPIRow, part.RowCount)
				require.NoError(t, parquet.Read(&rows))
				parquet.ReadStop()
				require.NoError(t, file.Close())
				for _, row := range rows {
					addresses = append(addresses, row.PhysicalAddress)
				}
			}
			require.ElementsMatch(t, expected, addresses)
			require.Equal(t, int64(len(expected)), manifest.TotalRows)
			if !crossRepository {
				require.Empty(t, manifest.Parts, "successful empty protection is explicit")
				require.Equal(t, int64(1), manifest.SourceCount)
			} else {
				require.Equal(t, int64(2), manifest.SourceCount)
			}
		})
	}
}

func TestGCReferencesAPIRejectsInvalidRequestsAndTaskTypes(t *testing.T) {
	client, deps, owner := setupGCReferencesAPI(t)
	ctx := t.Context()
	for _, minimumAge := range []int64{-1, 0, math.MaxInt64} {
		response, err := client.PrepareGarbageCollectionReferencesAsyncWithResponse(ctx, owner.Name, apigen.PrepareGarbageCollectionReferencesAsyncJSONRequestBody{MinimumAgeSeconds: &minimumAge})
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, response.StatusCode(), string(response.Body))
	}
	started, err := client.PrepareGarbageCollectionReferencesAsyncWithResponse(ctx, owner.Name, apigen.PrepareGarbageCollectionReferencesAsyncJSONRequestBody{})
	verifyResponseOK(t, started, err)
	status := waitGCReferencesAPI(t, client, owner.Name, started.JSON202.Id)
	require.Nil(t, status.Error)
	require.NotNil(t, status.Result)
	for _, id := range []string{catalog.NewTaskID(catalog.GCReferencesTaskPrefix), catalog.NewTaskID(catalog.GarbageCollectionPrepareCommitsPrefix)} {
		response, err := client.PrepareGarbageCollectionReferencesStatusWithResponse(ctx, owner.Name, &apigen.PrepareGarbageCollectionReferencesStatusParams{Id: id})
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, response.StatusCode(), string(response.Body))
	}
	other, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "view-store", "mem://views/other", "main", false)
	require.NoError(t, err)
	wrongRepo, err := client.PrepareGarbageCollectionReferencesStatusWithResponse(ctx, other.Name, &apigen.PrepareGarbageCollectionReferencesStatusParams{Id: status.TaskId})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, wrongRepo.StatusCode(), string(wrongRepo.Body))

	legacy, err := client.PrepareGarbageCollectionCommitsStatusWithResponse(ctx, owner.Name, &apigen.PrepareGarbageCollectionCommitsStatusParams{Id: status.TaskId})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, legacy.StatusCode(), string(legacy.Body))
	dump, err := client.DumpStatusWithResponse(ctx, owner.Name, &apigen.DumpStatusParams{TaskId: status.TaskId})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, dump.StatusCode(), string(dump.Body))
	restored, err := client.RestoreStatusWithResponse(ctx, owner.Name, &apigen.RestoreStatusParams{TaskId: status.TaskId})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, restored.StatusCode(), string(restored.Body))
}

func TestGCReferencesAPIFailedPreparationHasNoResult(t *testing.T) {
	client, deps, owner := setupGCReferencesAPI(t)
	view, err := deps.catalog.CreateRepository(t.Context(), testUniqueRepoName(), "view-store", "mem://views/repository", "main", false)
	require.NoError(t, err)
	entry := catalog.NewDBEntryBuilder().Path("unresolved").StorageID("missing-source").AddressType(catalog.AddressTypeFull).
		PhysicalAddress(owner.StorageNamespace + "/data/object").CreationDate(time.Now()).Checksum("etag").Size(1).Build()
	require.NoError(t, deps.catalog.CreateEntry(t.Context(), view.Name, "main", entry))
	started, err := client.PrepareGarbageCollectionReferencesAsyncWithResponse(t.Context(), owner.Name, apigen.PrepareGarbageCollectionReferencesAsyncJSONRequestBody{})
	verifyResponseOK(t, started, err)
	status := waitGCReferencesAPI(t, client, owner.Name, started.JSON202.Id)
	require.NotNil(t, status.Error)
	require.Contains(t, status.Error.Message, "missing-source")
	require.Nil(t, status.Result, "failed protection preparation cannot authorize a collector")
}
