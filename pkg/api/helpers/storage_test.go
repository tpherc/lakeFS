package helpers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/api/helpers"
	"github.com/treeverse/lakefs/pkg/uri"
)

func TestDownloaderUsesSourceSigningCapabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"storage_config_list":[{"blockstore_id":"signed","pre_sign_support":true},{"blockstore_id":"proxied","pre_sign_support":false}],"version_config":{}}`))
		case "/api/v1/repositories/repo/refs/main/objects":
			require.Equal(t, r.URL.Query().Get("path") == "signed", r.URL.Query().Get("presign") == "true")
			_, _ = w.Write([]byte("content"))
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := apigen.NewClientWithResponses(server.URL + "/api/v1")
	require.NoError(t, err)
	downloader := helpers.NewDownloader(client, true)
	for _, source := range []string{"proxied", "signed", "missing"} {
		t.Run(source, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "object")
			sourceURI := uri.URI{Repository: "repo", Ref: "main", Path: swag.String(source)}
			require.NoError(t, downloader.DownloadWithObjectInfo(t.Context(), sourceURI, destination, nil, &apigen.ObjectStats{
				StorageId: swag.String(source), SizeBytes: swag.Int64(7),
			}))
			content, err := os.ReadFile(destination)
			require.NoError(t, err)
			require.Equal(t, "content", string(content))
			require.True(t, downloader.PreSign, "per-object choices must not mutate the shared downloader")
		})
	}
}

func TestDownloaderLooksUpBindingBeforePresigning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"storage_config_list":[{"blockstore_id":"source","pre_sign_support":false}],"version_config":{}}`))
		case "/api/v1/repositories/repo/refs/main/objects/stat":
			require.Equal(t, "false", r.URL.Query().Get("presign"))
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(apigen.ObjectStats{StorageId: swag.String("source"), SizeBytes: swag.Int64(7)}))
		case "/api/v1/repositories/repo/refs/main/objects":
			require.Equal(t, "false", r.URL.Query().Get("presign"))
			_, _ = w.Write([]byte("content"))
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := apigen.NewClientWithResponses(server.URL + "/api/v1")
	require.NoError(t, err)
	downloader := helpers.NewDownloader(client, true)
	require.NoError(t, downloader.Download(t.Context(), uri.URI{Repository: "repo", Ref: "main", Path: swag.String("object")}, filepath.Join(t.TempDir(), "object"), nil))
}

func TestDownloaderExplicitPresignReachesSource(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/api/v1/repositories/repo/refs/main/objects", r.URL.Path, "explicit reads must not select home capabilities")
				require.Equal(t, fmt.Sprint(explicit), r.URL.Query().Get("presign"))
				if explicit {
					http.Error(w, "source cannot sign", http.StatusBadRequest)
					return
				}
				_, _ = w.Write([]byte("content"))
			}))
			defer server.Close()
			client, err := apigen.NewClientWithResponses(server.URL + "/api/v1")
			require.NoError(t, err)
			downloader := helpers.NewDownloader(client, !explicit)
			downloader.ReadPresign = swag.Bool(explicit)
			err = downloader.DownloadWithObjectInfo(t.Context(), uri.URI{Repository: "repo", Ref: "main", Path: swag.String("object")}, filepath.Join(t.TempDir(), "object"), nil, &apigen.ObjectStats{StorageId: swag.String("source"), SizeBytes: swag.Int64(7)})
			if explicit {
				require.ErrorIs(t, err, helpers.ErrRequestFailed)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
