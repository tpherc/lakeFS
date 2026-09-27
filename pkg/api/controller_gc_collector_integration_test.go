package api_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
)

// Run explicitly after assembling the collector. The classpath supplies Spark's
// provided runtime dependencies; the assembled jar must be first on that path.
func TestGCAssembledCollectorAgainstServer(t *testing.T) {
	jar := os.Getenv("LAKEFS_GC_ASSEMBLY_JAR")
	classpath := os.Getenv("LAKEFS_GC_COLLECTOR_CLASSPATH")
	if jar == "" || classpath == "" {
		t.Skip("set LAKEFS_GC_ASSEMBLY_JAR and LAKEFS_GC_COLLECTOR_CLASSPATH to run the assembled collector integration")
	}
	java := os.Getenv("LAKEFS_GC_JAVA")
	if java == "" {
		java = "java"
	}
	archive, err := zip.OpenReader(jar)
	require.NoError(t, err)
	entries := make(map[string]bool)
	for _, file := range archive.File {
		entries[file.Name] = true
	}
	require.NoError(t, archive.Close())
	require.True(t, entries["io/treeverse/gc/GarbageCollection.class"], "collector must come from the assembled jar")
	require.True(t, entries["io/lakefs/clients/sdk/model/PrepareGarbageCollectionReferencesRequest.class"], "assembly must contain the new SDK")

	ownerStore := newGCReferencesS3Endpoint(t)
	foreignStore := newGCReferencesS3Endpoint(t)
	client, deps := setupObjectBindingsClient(t, []map[string]any{
		bindingS3Store("home", ownerStore.URL, "gc-access-key", true),
		bindingS3Store("foreign", foreignStore.URL, "gc-access-key", false),
		{"id": "views", "type": "mem"},
	})
	ctx := t.Context()
	owner, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "home", "s3://gc-bucket/owner", "main", false)
	require.NoError(t, err)
	view, err := deps.catalog.CreateRepository(ctx, testUniqueRepoName(), "views", "mem://views/catalog", "main", false)
	require.NoError(t, err)
	seed := func(endpoint, key string, modified time.Time) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint+"/gc-bucket/"+key, strings.NewReader("bytes for "+key))
		require.NoError(t, err)
		request.Header.Set("Authorization", "fixture gc-access-key/")
		request.Header.Set("X-Test-Modified-At", modified.UTC().Format(time.RFC3339))
		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NoError(t, response.Body.Close())
	}
	old := time.Now().Add(-7 * 24 * time.Hour)
	for _, key := range []string{"data/history", "data/staged", "data/unreferenced", "legacy:unreferenced", "_lakefs/internal-keep", "imported/keep"} {
		seed(ownerStore.URL, "owner/"+key, old)
	}
	seed(ownerStore.URL, "owner/data/young", time.Now())
	seed(ownerStore.URL, "ownership/data/outside", old)
	seed(foreignStore.URL, "owner/data/unreferenced", old)
	putReference := func(path, key, storageID string) {
		t.Helper()
		entry := catalog.NewDBEntryBuilder().Path(path).StorageID(storageID).AddressType(catalog.AddressTypeFull).
			PhysicalAddress(owner.StorageNamespace + "/" + key).CreationDate(time.Now()).Checksum("etag").Size(1).Build()
		require.NoError(t, deps.catalog.CreateEntry(ctx, view.Name, "main", entry))
	}
	putReference("historical", "data/history", "home")
	committed, err := client.CommitWithResponse(ctx, view.Name, "main", &apigen.CommitParams{}, apigen.CommitJSONRequestBody{Message: "reference owner data"})
	verifyResponseOK(t, committed, err)
	deleted, err := client.DeleteObjectWithResponse(ctx, view.Name, "main", &apigen.DeleteObjectParams{Path: "historical"})
	verifyResponseOK(t, deleted, err)
	committed, err = client.CommitWithResponse(ctx, view.Name, "main", &apigen.CommitParams{}, apigen.CommitJSONRequestBody{Message: "history remains protected without a policy"})
	verifyResponseOK(t, committed, err)
	putReference("staged", "data/staged", "home")
	putReference("foreign", "data/unreferenced", "foreign")
	putReference("metadata", "_lakefs/internal-keep", "home")
	putReference("outside-data", "imported/keep", "home")

	apiClient := client.(*apigen.ClientWithResponses).ClientInterface.(*apigen.Client)
	apiEndpoint := apiClient.Server
	authRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	require.NoError(t, err)
	for _, edit := range apiClient.RequestEditors {
		require.NoError(t, edit(ctx, authRequest))
	}
	accessKey, secretKey, hasAuth := authRequest.BasicAuth()
	require.True(t, hasAuth, "use the fixture's existing administrator credentials")
	args := []string{"-Xmx1g", "-XX:ActiveProcessorCount=4", "-XX:+IgnoreUnrecognizedVMOptions"}
	for _, module := range []string{
		"java.base/java.lang", "java.base/java.lang.invoke", "java.base/java.lang.reflect", "java.base/java.io",
		"java.base/java.net", "java.base/java.nio", "java.base/java.util", "java.base/java.util.concurrent",
		"java.base/java.util.concurrent.atomic", "java.base/jdk.internal.ref", "java.base/sun.nio.ch",
		"java.base/sun.nio.cs", "java.base/sun.security.action", "java.base/sun.util.calendar",
		"java.security.jgss/sun.security.krb5",
	} {
		args = append(args, "--add-opens="+module+"=ALL-UNNAMED")
	}
	properties := map[string]string{
		"spark.master": "local[2]", "spark.ui.enabled": "false", "spark.sql.shuffle.partitions": "2",
		"spark.driver.bindAddress": "127.0.0.1", "spark.driver.host": "localhost",
		"spark.local.dir": t.TempDir(), "spark.hadoop.lakefs.api.url": strings.TrimSuffix(apiEndpoint, "/"),
		"spark.hadoop.lakefs.api.access_key": accessKey,
		"spark.hadoop.lakefs.api.secret_key": secretKey,
		"spark.hadoop.lakefs.gc.do_mark":     "true", "spark.hadoop.lakefs.gc.do_sweep": "true",
		"spark.hadoop.fs.s3a.endpoint": ownerStore.URL, "spark.hadoop.fs.s3a.endpoint.region": "us-east-1",
		"spark.hadoop.fs.s3a.path.style.access": "true", "spark.hadoop.fs.s3a.connection.ssl.enabled": "false",
		"spark.hadoop.fs.s3a.access.key": "gc-access-key", "spark.hadoop.fs.s3a.secret.key": "test-only-secret",
		"spark.hadoop.fs.s3a.aws.credentials.provider": "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
		"spark.hadoop.fs.s3a.retry.limit":              "1", "spark.hadoop.fs.s3a.retry.interval": "10ms",
		"spark.hadoop.fs.s3a.attempts.maximum": "1",
	}
	runCollector := func(mark, sweep bool, markID string) {
		t.Helper()
		properties["spark.hadoop.lakefs.gc.do_mark"] = fmt.Sprint(mark)
		properties["spark.hadoop.lakefs.gc.do_sweep"] = fmt.Sprint(sweep)
		properties["spark.hadoop.lakefs.gc.mark_id"] = markID
		commandArgs := append([]string(nil), args...)
		for key, value := range properties {
			commandArgs = append(commandArgs, "-D"+key+"="+value)
		}
		commandArgs = append(commandArgs, "-cp", jar+string(os.PathListSeparator)+classpath, "io.treeverse.gc.GarbageCollection", owner.Name, "us-east-1")
		processCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		command := exec.CommandContext(processCtx, java, commandArgs...)
		command.Env = append(os.Environ(), "SPARK_LOCAL_IP=127.0.0.1", "AWS_EC2_METADATA_DISABLED=true")
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		err := command.Run()
		logPath := filepath.Join(t.TempDir(), "collector.log")
		require.NoError(t, os.WriteFile(logPath, output.Bytes(), 0o600))
		requireGCCollectorSuccess(t, err, mark, sweep, output.String())
	}
	exists := func(storageID, location string) bool {
		t.Helper()
		found, err := deps.blocks.Exists(ctx, block.ObjectPointer{StorageID: storageID, Identifier: location, IdentifierType: block.IdentifierTypeFull})
		require.NoError(t, err)
		return found
	}
	runCollector(true, false, "")
	markLocation := gcCollectorMarkLocation(t, ownerStore.URL)
	mark := readGCReferencesArtifact(t, deps, markLocation)
	markID := strings.TrimSuffix(strings.TrimPrefix(markLocation, owner.StorageNamespace+"/_lakefs/retention/gc/unified/"), "/candidates.json")
	for _, key := range []string{"data/unreferenced", "legacy:unreferenced"} {
		require.True(t, exists("home", owner.StorageNamespace+"/"+key), "mark-only must not delete %s", key)
	}
	runCollector(false, true, markID)
	require.Equal(t, mark, readGCReferencesArtifact(t, deps, markLocation), "sweep must preserve the immutable mark")
	seed(ownerStore.URL, "owner/data/combined-only", old)
	runCollector(true, true, "")
	require.False(t, exists("home", owner.StorageNamespace+"/data/combined-only"))
	for _, key := range []string{"data/history", "data/staged", "data/young", "_lakefs/internal-keep", "imported/keep"} {
		require.True(t, exists("home", owner.StorageNamespace+"/"+key), "must preserve %s", key)
	}
	for _, key := range []string{"data/unreferenced", "legacy:unreferenced"} {
		require.False(t, exists("home", owner.StorageNamespace+"/"+key), "must delete %s", key)
	}
	require.True(t, exists("home", "s3://gc-bucket/ownership/data/outside"))
	require.True(t, exists("foreign", owner.StorageNamespace+"/data/unreferenced"))
	// Ensure preserved source bytes, rather than merely their catalog metadata, survive.
	body, err := deps.blocks.Get(ctx, block.ObjectPointer{StorageID: "home", Identifier: owner.StorageNamespace + "/data/history", IdentifierType: block.IdentifierTypeFull})
	require.NoError(t, err)
	content, err := io.ReadAll(body)
	require.NoError(t, err)
	require.NoError(t, body.Close())
	require.Contains(t, string(content), "owner/data/history")

	// Removing the source repository removes its live and retained history from
	// this installation. A new mark can now release the formerly protected bytes.
	require.NoError(t, deps.catalog.DeleteRepository(ctx, view.Name))
	runCollector(true, true, "")
	for _, key := range []string{"data/history", "data/staged"} {
		require.False(t, exists("home", owner.StorageNamespace+"/"+key), "new marking must release %s after its last protection disappears", key)
	}
	for _, key := range []string{"data/young", "_lakefs/internal-keep", "imported/keep"} {
		require.True(t, exists("home", owner.StorageNamespace+"/"+key))
	}
	require.True(t, exists("foreign", owner.StorageNamespace+"/data/unreferenced"))
}

// Discover the single mark via the isolated service's paginated listing, just as
// an operator can obtain its run ID from the published report location.
func gcCollectorMarkLocation(t *testing.T, endpoint string) string {
	t.Helper()
	var locations []string
	token := ""
	for page := 0; page < 100; page++ {
		query := url.Values{"list-type": {"2"}, "prefix": {"owner/_lakefs/retention/gc/unified/"}}
		if token != "" {
			query.Set("continuation-token", token)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint+"/gc-bucket?"+query.Encode(), nil)
		require.NoError(t, err)
		request.Header.Set("Authorization", "fixture gc-access-key/")
		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		var listing struct {
			IsTruncated           bool
			NextContinuationToken string
			Contents              []struct{ Key string }
		}
		err = xml.NewDecoder(response.Body).Decode(&listing)
		require.NoError(t, response.Body.Close())
		require.NoError(t, err)
		for _, item := range listing.Contents {
			if strings.HasSuffix(item.Key, "/candidates.json") {
				locations = append(locations, "s3://gc-bucket/"+item.Key)
			}
		}
		if !listing.IsTruncated {
			require.Len(t, locations, 1)
			return locations[0]
		}
		require.NotEmpty(t, listing.NextContinuationToken)
		require.NotEqual(t, token, listing.NextContinuationToken)
		token = listing.NextContinuationToken
	}
	t.Fatal("fixture listing exceeded page limit")
	return ""
}

func requireGCCollectorSuccess(t *testing.T, err error, mark, sweep bool, output string) {
	t.Helper()
	if err == nil {
		return
	}
	if len(output) > 18000 {
		output = output[len(output)-18000:]
	}
	t.Fatalf("assembled collector (mark=%t sweep=%t) failed: %v\n%s", mark, sweep, err, output)
}
