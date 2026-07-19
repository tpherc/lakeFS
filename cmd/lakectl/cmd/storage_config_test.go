package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	lakefsconfig "github.com/treeverse/lakefs/pkg/config"
)

func TestGetStorageConfigOrDieReturnsSingleListEntryWithoutRepositoryLookup(t *testing.T) {
	repositoryCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"storage_config_list": [
					{"blockstore_id": "alpha", "blockstore_type": "mem", "pre_sign_support": true}
				],
				"version_config": {}
			}`)
		case "/api/v1/repositories/repo1":
			repositoryCalls++
			http.Error(w, "unexpected repository lookup", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	storageConfig := getStorageConfigOrDie(t.Context(), getTestClient(t, server.URL), "repo1")
	require.Equal(t, "alpha", *storageConfig.BlockstoreId)
	require.True(t, storageConfig.PreSignSupport)
	require.Zero(t, repositoryCalls)
}

func TestGetStorageConfigOrDieSelectsRepositoryStorageFromList(t *testing.T) {
	repositoryCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/config":
			_, _ = io.WriteString(w, `{
				"storage_config_list": [
					{"blockstore_id": "alpha", "blockstore_type": "mem", "pre_sign_support": false},
					{"blockstore_id": "beta", "blockstore_type": "mem", "pre_sign_support": true}
				],
				"version_config": {}
			}`)
		case "/api/v1/repositories/repo1":
			repositoryCalls++
			_, _ = io.WriteString(w, `{
				"id": "repo1",
				"default_branch": "main",
				"storage_namespace": "mem://repo1",
				"storage_id": "beta",
				"creation_date": 1
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	storageConfig := getStorageConfigOrDie(t.Context(), getTestClient(t, server.URL), "repo1")
	require.Equal(t, "beta", *storageConfig.BlockstoreId)
	require.True(t, storageConfig.PreSignSupport)
	require.Equal(t, 1, repositoryCalls)
}

func TestLakectlRepoCreateAllowsEmptyStorageID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/repositories", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "", body["storage_id"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{
			"id": "repo1",
			"default_branch": "main",
			"storage_namespace": "mem://repo1",
			"creation_date": 1
		}`)
	}))
	defer server.Close()

	runRepoCreateForTest(t, server.URL, "")
}

func TestLakectlRepoCreateRejectsNonEmptyStorageIDInSingleBackend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/repositories", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "storage1", body["storage_id"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message": "storage id: invalid value"}`)
	}))
	defer server.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestLakectlRepoCreateRejectsNonEmptyStorageIDHelper$")
	cmd.Env = append(os.Environ(), "LAKECTL_REPO_CREATE_FAILURE_ENDPOINT="+server.URL)
	output, err := cmd.CombinedOutput()
	require.Error(t, err, string(output))
	require.Contains(t, string(output), "storage id: invalid value")
}

func TestLakectlRepoCreateRejectsNonEmptyStorageIDHelper(t *testing.T) {
	endpoint := os.Getenv("LAKECTL_REPO_CREATE_FAILURE_ENDPOINT")
	if endpoint == "" {
		return
	}
	runRepoCreateForTest(t, endpoint, "storage1")
	t.Fatal("expected repo create to exit")
}

func runRepoCreateForTest(t *testing.T, endpoint, storageID string) {
	t.Helper()
	originalCfg := cfg
	cfg = &Configuration{}
	cfg.Server.EndpointURL = lakefsconfig.OnlyString(endpoint)
	t.Cleanup(func() {
		cfg = originalCfg
	})

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.Flags().StringP(defaultBranchFlagName, "d", defaultBranchFlagValue, "")
	cmd.Flags().Bool(sampleDataFlagName, false, "")
	withStorageID(cmd)
	require.NoError(t, cmd.Flags().Set(storageIDFlagName, storageID))

	repoCreateCmd.Run(cmd, []string{"lakefs://repo1", "mem://repo1"})
}
