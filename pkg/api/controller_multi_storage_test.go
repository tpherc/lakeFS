package api_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/api/apiutil"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestControllerCreateRepositoryMultiStorageIsolation(t *testing.T) {
	viper.Set("blockstores.signing.secret_key", "signing")
	viper.Set("blockstores.stores", []map[string]any{
		{
			"id":                  "alpha",
			"type":                block.BlockstoreTypeMem,
			"backward_compatible": true,
		},
		{
			"id":   "beta",
			"type": block.BlockstoreTypeMem,
		},
	})
	t.Cleanup(func() {
		viper.Set("blockstores.stores", nil)
		viper.Set("blockstores.signing.secret_key", nil)
		viper.Set(config.BlockstoreTypeKey, nil)
	})

	handler, deps := setupHandler(t)
	server := setupServer(t, handler)
	clt := setupClientByEndpoint(t, server.URL, "", "")
	cred := createDefaultAdminUser(t, clt)
	clt = setupClientByEndpoint(t, server.URL, cred.AccessKeyID, cred.SecretAccessKey)

	ctx := t.Context()
	alphaNamespace := "mem://alpha-repo"
	alphaResp, err := clt.CreateRepositoryWithResponse(ctx, &apigen.CreateRepositoryParams{}, apigen.CreateRepositoryJSONRequestBody{
		DefaultBranch:    apiutil.Ptr("main"),
		Name:             testUniqueRepoName(),
		StorageId:        swag.String("alpha"),
		StorageNamespace: alphaNamespace,
	})
	verifyResponseOK(t, alphaResp, err)
	require.NotNil(t, alphaResp.JSON201)
	require.Equal(t, "alpha", swag.StringValue(alphaResp.JSON201.StorageId))

	betaNamespace := "mem://beta-repo"
	betaResp, err := clt.CreateRepositoryWithResponse(ctx, &apigen.CreateRepositoryParams{}, apigen.CreateRepositoryJSONRequestBody{
		DefaultBranch:    apiutil.Ptr("main"),
		Name:             testUniqueRepoName(),
		StorageId:        swag.String("beta"),
		StorageNamespace: betaNamespace,
	})
	verifyResponseOK(t, betaResp, err)
	require.NotNil(t, betaResp.JSON201)
	require.Equal(t, "beta", swag.StringValue(betaResp.JSON201.StorageId))

	_, err = deps.blocks.Put(ctx, block.ObjectPointer{
		StorageID:        "alpha",
		StorageNamespace: alphaNamespace,
		Identifier:       "same-key",
		IdentifierType:   block.IdentifierTypeRelative,
	}, int64(len("alpha")), strings.NewReader("alpha"), block.PutOpts{})
	require.NoError(t, err)

	existsAlpha, err := deps.blocks.Exists(ctx, block.ObjectPointer{
		StorageID:        "alpha",
		StorageNamespace: alphaNamespace,
		Identifier:       "same-key",
		IdentifierType:   block.IdentifierTypeRelative,
	})
	require.NoError(t, err)
	require.True(t, existsAlpha)

	existsBeta, err := deps.blocks.Exists(ctx, block.ObjectPointer{
		StorageID:        "beta",
		StorageNamespace: betaNamespace,
		Identifier:       "same-key",
		IdentifierType:   block.IdentifierTypeRelative,
	})
	require.NoError(t, err)
	require.False(t, existsBeta)
}

func TestControllerCreateRepositoryOmittedStorageIDPersistsCompatibleStore(t *testing.T) {
	viper.Set("blockstores.signing.secret_key", "signing")
	viper.Set("blockstores.stores", []map[string]any{
		{
			"id":                  "alpha",
			"type":                block.BlockstoreTypeMem,
			"backward_compatible": true,
		},
		{
			"id":   "beta",
			"type": block.BlockstoreTypeMem,
		},
	})
	t.Cleanup(func() {
		viper.Set("blockstores.stores", nil)
		viper.Set("blockstores.signing.secret_key", nil)
	})

	handler, _ := setupHandler(t)
	server := setupServer(t, handler)
	clt := setupClientByEndpoint(t, server.URL, "", "")
	cred := createDefaultAdminUser(t, clt)
	clt = setupClientByEndpoint(t, server.URL, cred.AccessKeyID, cred.SecretAccessKey)

	resp, err := clt.CreateRepositoryWithResponse(t.Context(), &apigen.CreateRepositoryParams{}, apigen.CreateRepositoryJSONRequestBody{
		DefaultBranch:    apiutil.Ptr("main"),
		Name:             testUniqueRepoName(),
		StorageNamespace: "mem://default-repo",
	})
	verifyResponseOK(t, resp, err)
	require.NotNil(t, resp.JSON201)
	require.Equal(t, "alpha", swag.StringValue(resp.JSON201.StorageId))
}

func TestControllerConfigMultiStorageRedactsSigningKey(t *testing.T) {
	const signingSecret = "sentinel-signing-secret"
	viper.Set("blockstores.signing.secret_key", signingSecret)
	viper.Set("blockstores.stores", []map[string]any{
		{
			"id":                  "alpha",
			"type":                block.BlockstoreTypeMem,
			"backward_compatible": true,
		},
		{
			"id":   "beta",
			"type": block.BlockstoreTypeMem,
		},
	})
	t.Cleanup(func() {
		viper.Set("blockstores.stores", nil)
		viper.Set("blockstores.signing.secret_key", nil)
	})

	handler, _ := setupHandler(t)
	server := setupServer(t, handler)
	clt := setupClientByEndpoint(t, server.URL, "", "")
	cred := createDefaultAdminUser(t, clt)
	clt = setupClientByEndpoint(t, server.URL, cred.AccessKeyID, cred.SecretAccessKey)

	resp, err := clt.GetConfigWithResponse(t.Context())
	verifyResponseOK(t, resp, err)
	require.NotNil(t, resp.JSON200)
	require.Nil(t, resp.JSON200.StorageConfig)
	require.NotNil(t, resp.JSON200.StorageConfigList)
	require.Len(t, *resp.JSON200.StorageConfigList, 2)
	require.Equal(t, "alpha", swag.StringValue((*resp.JSON200.StorageConfigList)[0].BlockstoreId))
	require.Equal(t, "beta", swag.StringValue((*resp.JSON200.StorageConfigList)[1].BlockstoreId))

	encoded, err := json.Marshal(resp.JSON200)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), signingSecret)
}
