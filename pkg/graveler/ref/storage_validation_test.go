package ref_test

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/ref"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/testutil"
)

type strictStorageConfig struct {
	configured map[string]struct{}
	compatible string
	multi      bool
}

func (s strictStorageConfig) GetStorageByID(storageID string) config.AdapterConfig {
	if !s.multi {
		if storageID != config.SingleBlockstoreID {
			return nil
		}
		return &AdapterConfigMock{id: config.SingleBlockstoreID}
	}
	if _, ok := s.configured[storageID]; !ok {
		return nil
	}
	return &AdapterConfigMock{id: storageID}
}

func (s strictStorageConfig) GetStorageIDs() []string {
	if !s.multi {
		return []string{config.SingleBlockstoreID}
	}
	ids := make([]string, 0, len(s.configured))
	for id := range s.configured {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s strictStorageConfig) ResolveNewRepositoryStorageID(storageID string) (string, error) {
	return s.resolve(storageID)
}

func (s strictStorageConfig) ResolveStoredRepositoryStorageID(storageID string) (string, error) {
	return s.resolve(storageID)
}

func (s strictStorageConfig) ValidateObjectStorageID(storageID string) error {
	_, err := s.resolve(storageID)
	return err
}

func (s strictStorageConfig) IsMultiStorage() bool {
	return s.multi
}

func (s strictStorageConfig) SigningKey() config.SecureString {
	return ""
}

func (s strictStorageConfig) resolve(storageID string) (string, error) {
	if !s.multi {
		if storageID == config.SingleBlockstoreID {
			return config.SingleBlockstoreID, nil
		}
		return "", fmt.Errorf("storage id %q: %w", storageID, config.ErrNoStorageConfig)
	}
	if storageID == config.SingleBlockstoreID {
		if s.compatible == "" {
			return "", fmt.Errorf("storage id %q: %w", storageID, config.ErrNoStorageConfig)
		}
		return s.compatible, nil
	}
	if _, ok := s.configured[storageID]; !ok {
		return "", fmt.Errorf("storage id %q: %w", storageID, config.ErrNoStorageConfig)
	}
	return storageID, nil
}

func TestValidateRepositoryStorageIDsResolvesLegacyEmptyWithoutPersisting(t *testing.T) {
	ctx := t.Context()
	r, store := testRefManager(t)
	_, err := r.CreateRepository(ctx, "legacy", graveler.Repository{
		StorageID:        config.SingleBlockstoreID,
		StorageNamespace: "s3://bucket",
		CreationDate:     time.Now(),
		DefaultBranchID:  "main",
	})
	testutil.Must(t, err)

	storageConfig := strictStorageConfig{
		configured: map[string]struct{}{"alpha": {}, "beta": {}},
		compatible: "alpha",
		multi:      true,
	}
	require.NoError(t, ref.ValidateRepositoryStorageIDs(ctx, store, storageConfig))

	iter, err := ref.NewRepositoryIterator(ctx, store, storageConfig)
	require.NoError(t, err)
	require.True(t, iter.Next())
	require.Equal(t, graveler.StorageID("alpha"), iter.Value().StorageID)
	require.NoError(t, iter.Err())

	raw := graveler.RepositoryData{}
	_, err = kv.GetMsg(ctx, store, graveler.RepositoriesPartition(), []byte(graveler.RepoPath("legacy")), &raw)
	require.NoError(t, err)
	require.Equal(t, config.SingleBlockstoreID, raw.StorageId)
}

func TestValidateRepositoryStorageIDsRejectsInvalidRepositoryState(t *testing.T) {
	ctx := t.Context()
	r, store := testRefManager(t)
	_, err := r.CreateRepository(ctx, "unknown", graveler.Repository{
		StorageID:        "removed",
		StorageNamespace: "s3://bucket",
		CreationDate:     time.Now(),
		DefaultBranchID:  "main",
	})
	testutil.Must(t, err)

	err = ref.ValidateRepositoryStorageIDs(ctx, store, strictStorageConfig{
		configured: map[string]struct{}{"alpha": {}},
		compatible: "alpha",
		multi:      true,
	})
	require.ErrorIs(t, err, config.ErrNoStorageConfig)

	err = ref.ValidateRepositoryStorageIDs(ctx, store, strictStorageConfig{multi: false})
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
}
