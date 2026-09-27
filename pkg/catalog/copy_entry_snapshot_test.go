package catalog

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/api/apiutil"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/upload"
)

type snapshotCopyStore struct {
	Store
	repositories map[graveler.RepositoryID]*graveler.RepositoryRecord
	latest       *graveler.Value
	getCalls     int
	written      *graveler.Value
}

func (s *snapshotCopyStore) GetRepository(_ context.Context, repositoryID graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	repository, ok := s.repositories[repositoryID]
	if !ok {
		return nil, graveler.ErrNotFound
	}
	return repository, nil
}

func (s *snapshotCopyStore) Get(_ context.Context, _ *graveler.RepositoryRecord, _ graveler.Ref, _ graveler.Key, _ ...graveler.GetOptionsFunc) (*graveler.Value, error) {
	s.getCalls++
	return s.latest, nil
}

func (s *snapshotCopyStore) Set(_ context.Context, _ *graveler.RepositoryRecord, _ graveler.BranchID, _ graveler.Key, value graveler.Value, _ ...graveler.SetOptionsFunc) error {
	s.written = &value
	return nil
}

type snapshotCopyAdapter struct {
	block.Adapter
	source      block.ObjectPointer
	destination block.ObjectPointer
	copyCalls   int
}

func (a *snapshotCopyAdapter) Copy(_ context.Context, source, destination block.ObjectPointer) error {
	a.source = source
	a.destination = destination
	a.copyCalls++
	return nil
}

func newSnapshotCopyCatalog() (*Catalog, *snapshotCopyStore, *snapshotCopyAdapter) {
	store := &snapshotCopyStore{repositories: map[graveler.RepositoryID]*graveler.RepositoryRecord{
		"repo": {RepositoryID: "repo", Repository: &graveler.Repository{StorageID: "store-a", StorageNamespace: "s3://bucket", DefaultBranchID: "main"}},
	}}
	adapter := &snapshotCopyAdapter{}
	return &Catalog{Store: store, BlockAdapter: adapter, PathProvider: upload.NewPathPartitionProvider()}, store, adapter
}

func TestCopyEntryFromSnapshot(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		shallow     bool
		replace     bool
		replacement Metadata
	}{
		{name: "full preserves metadata"},
		{name: "full replaces metadata", replace: true, replacement: Metadata{"dcs:cls": "R"}},
		{name: "shallow preserves metadata", shallow: true},
		{name: "shallow replaces metadata", shallow: true, replace: true, replacement: Metadata{"dcs:cls": "R"}},
		{name: "shallow clears metadata", shallow: true, replace: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			catalog, store, adapter := newSnapshotCopyCatalog()
			snapshot := &DBEntry{Path: "document", PhysicalAddress: "authorized-object", CreationDate: time.Now(), AddressType: AddressTypeRelative, Metadata: Metadata{"dcs:cls": "U"}}
			original := *snapshot
			original.Metadata = maps.Clone(snapshot.Metadata)
			replacementBefore := maps.Clone(tt.replacement)
			latest := *snapshot
			latest.PhysicalAddress = "unauthorized-replacement"
			latest.Metadata = Metadata{"dcs:cls": "TS"}
			var err error
			store.latest, err = EntryToValue(newEntryFromCatalogEntry(latest))
			require.NoError(t, err)

			result, err := catalog.CopyEntryFromSnapshot(t.Context(), "repo", "main", snapshot, "repo", "main", "copy", tt.replace, tt.replacement, func(options *graveler.SetOptions) { options.Shallow = tt.shallow })
			require.NoError(t, err)
			require.Zero(t, store.getCalls, "must not resolve a newer source entry after authorization")
			require.Equal(t, original, *snapshot, "the authorized snapshot must remain immutable")
			require.Equal(t, replacementBefore, tt.replacement, "copy must not add internal metadata to caller input")
			require.Equal(t, "copy", result.Path)
			wantMetadata := Metadata{"dcs:cls": "U"}
			if tt.replace {
				wantMetadata = maps.Clone(tt.replacement)
			}
			if tt.shallow {
				if wantMetadata == nil {
					wantMetadata = make(Metadata)
				}
				wantMetadata[apiutil.CloneMetadataKey] = snapshot.Path
				require.Zero(t, adapter.copyCalls)
				require.Equal(t, snapshot.PhysicalAddress, result.PhysicalAddress)
			} else {
				require.Equal(t, 1, adapter.copyCalls)
				require.Equal(t, "authorized-object", adapter.source.Identifier)
				require.Equal(t, "store-a", adapter.source.StorageID)
				require.Equal(t, result.PhysicalAddress, adapter.destination.Identifier)
				require.NotEqual(t, snapshot.PhysicalAddress, result.PhysicalAddress)
			}
			require.Equal(t, wantMetadata, result.Metadata)
			written, err := ValueToEntry(store.written)
			require.NoError(t, err)
			require.Equal(t, result.PhysicalAddress, written.Address)
			require.EqualValues(t, wantMetadata, written.Metadata)
		})
	}
}

func TestCopyEntryLoadsSourceOnce(t *testing.T) {
	t.Parallel()
	catalog, store, adapter := newSnapshotCopyCatalog()
	var err error
	store.latest, err = EntryToValue(newEntryFromCatalogEntry(DBEntry{Path: "source", PhysicalAddress: "source-object", AddressType: AddressTypeRelative, CreationDate: time.Now(), Metadata: Metadata{"dcs:cls": "S"}}))
	require.NoError(t, err)
	result, err := catalog.CopyEntry(t.Context(), "repo", "main", "source", "repo", "main", "copy", false, nil)
	require.NoError(t, err)
	require.Equal(t, 1, store.getCalls)
	require.Equal(t, "source-object", adapter.source.Identifier)
	require.Equal(t, Metadata{"dcs:cls": "S"}, result.Metadata)
}

func TestCopyEntryFromSnapshotPreservesCopyRestrictions(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name          string
		destination   string
		storageID     graveler.StorageID
		branch        string
		shallow       bool
		expectedError error
	}{
		{"different storage", "other", "store-b", "main", false, graveler.ErrInvalidStorageID},
		{"shallow different repository", "other", "store-a", "main", true, graveler.ErrCannotClone},
		{"shallow different branch", "repo", "store-a", "other", true, graveler.ErrCannotClone},
	} {
		t.Run(tt.name, func(t *testing.T) {
			catalog, store, adapter := newSnapshotCopyCatalog()
			store.repositories["other"] = &graveler.RepositoryRecord{RepositoryID: "other", Repository: &graveler.Repository{StorageID: tt.storageID, StorageNamespace: "s3://other"}}
			_, err := catalog.CopyEntryFromSnapshot(t.Context(), "repo", "main", &DBEntry{Path: "source"}, tt.destination, tt.branch, "copy", false, nil, func(options *graveler.SetOptions) { options.Shallow = tt.shallow })
			require.True(t, errors.Is(err, tt.expectedError), "got %v", err)
			require.Zero(t, adapter.copyCalls)
			require.Nil(t, store.written)
		})
	}
}
