package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestS3CustomEndpointConfiguration(t *testing.T) {
	for _, mode := range []string{"single", "multi"} {
		t.Run(mode, func(t *testing.T) {
			body := "database:\n  type: local\nauth:\n  encrypt:\n    secret_key: auth-secret\n"
			id := ""
			if mode == "single" {
				body += "blockstore:\n  type: s3\n  s3:\n    endpoint: https://objects.example\n    force_path_style: true\n"
			} else {
				id = "home"
				body += "blockstores:\n  signing:\n    secret_key: signing-secret\n  stores:\n    - id: home\n      type: s3\n      s3:\n        endpoint: https://objects.example\n        force_path_style: true\n"
			}
			cfg, err := buildConfigFromYAML(t, body)
			require.NoError(t, err)
			params, err := cfg.StorageConfig().GetStorageByID(id).BlockstoreS3Params()
			require.NoError(t, err)
			require.Equal(t, "https://objects.example", params.Endpoint)
			require.True(t, params.ForcePathStyle)
		})
	}
}
