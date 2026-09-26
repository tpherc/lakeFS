package catalog

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/golang/mock/gomock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/committed"
	committedmock "github.com/treeverse/lakefs/pkg/graveler/committed/mock"
	gtest "github.com/treeverse/lakefs/pkg/graveler/testutil"
	"github.com/treeverse/lakefs/pkg/ident"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/upload"
	"github.com/xitongsys/parquet-go-source/buffer"
	"github.com/xitongsys/parquet-go/reader"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStorageBindingIdentity(t *testing.T) {
	t.Parallel()
	entry := &Entry{Size: 19, ETag: "etag", Metadata: map[string]string{"key": "value"}, ContentType: "text/plain"}
	legacyIdentity := ident.NewAddressWriter().MarshalInt64(19).MarshalString("etag").MarshalStringMap(entry.Metadata).MarshalStringOpt("text/plain").Identity()
	value := MustEntryToValue(entry)
	require.Equal(t, hex.EncodeToString(legacyIdentity), hex.EncodeToString(value.Identity), "empty storage ID must preserve the pre-extension identity")

	entry.StorageId = "source"
	bound := MustEntryToValue(entry)
	require.NotEqual(t, value.Identity, bound.Identity)
	decoded, err := ValueToEntry(bound)
	require.NoError(t, err)
	require.Equal(t, "source", decoded.StorageId)

	// Two optional strings would collide when one entry supplies content type and another supplies the ID.
	contentTypeOnly := MustEntryToValue(&Entry{Size: 19, ETag: "etag", ContentType: "source"})
	bindingOnly := MustEntryToValue(&Entry{Size: 19, ETag: "etag", StorageId: "source"})
	require.NotEqual(t, contentTypeOnly.Identity, bindingOnly.Identity)
}

func TestBindingOnlyRelinkSurvivesCommit(t *testing.T) {
	t.Parallel()
	baseEntry := &Entry{Address: "s3://bucket/key", AddressType: Entry_FULL, StorageId: "source-a", Size: 12, ETag: "same-etag"}
	newEntry := proto.Clone(baseEntry).(*Entry)
	newEntry.StorageId = "source-b"
	baseValue := &graveler.ValueRecord{Key: []byte("object"), Value: MustEntryToValue(baseEntry)}
	changeValue := graveler.ValueRecord{Key: []byte("object"), Value: MustEntryToValue(newEntry)}
	base := gtest.NewFakeIterator().AddRange(&committed.Range{ID: "range", MinKey: []byte("object"), MaxKey: []byte("object"), Count: 1}).AddValueRecords(baseValue)
	changes := gtest.NewValueIteratorFake([]graveler.ValueRecord{changeValue})
	writer := committedmock.NewMockMetaRangeWriter(gomock.NewController(t))
	writer.EXPECT().WriteRecord(gomock.Eq(changeValue))
	summary, err := committed.Commit(t.Context(), writer, base, changes, &committed.CommitOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, summary.Count[graveler.DiffTypeChanged])
}

func TestStorageBindingHistoryMergeAndRevert(t *testing.T) {
	viper.Set("blockstores.signing.secret_key", "test-signing-key")
	viper.Set("blockstores.stores", []map[string]any{
		{"id": "home", "type": "mem"},
		{"id": "source-a", "type": "mem"},
		{"id": "source-b", "type": "mem"},
	})
	viper.Set("committed.local_cache.size_bytes", 24*1024*1024)
	viper.Set("committed.sstable.memory.cache_size_bytes", 2*1024*1024)
	t.Cleanup(viper.Reset)
	cfg := &config.ConfigImpl{}
	_, err := config.NewConfig("", cfg)
	require.NoError(t, err)
	cfg.Committed.LocalCache.Dir = filepath.Join(t.TempDir(), "cache")
	ctx := t.Context()
	c, err := New(ctx, Config{Config: cfg, KVStore: kvtest.GetStore(ctx, t), PathProvider: upload.NewPathPartitionProvider()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	_, err = c.CreateRepository(ctx, "history-repo", "home", "mem://history-repo", "main", false)
	require.NoError(t, err)

	entry := DBEntry{Path: "object", PhysicalAddress: "mem://source/object", AddressType: AddressTypeFull, StorageID: "source-a", CreationDate: time.Now(), Size: 12, Checksum: "same-etag"}
	require.NoError(t, c.CreateEntry(ctx, "history-repo", "main", entry))
	base, err := c.Commit(ctx, "history-repo", "main", "original source", "tester", nil, nil, nil, false)
	require.NoError(t, err)
	_, err = c.CreateBranch(ctx, "history-repo", "change", "main")
	require.NoError(t, err)
	entry.StorageID = "source-b"
	require.NoError(t, c.CreateEntry(ctx, "history-repo", "change", entry))
	relinked, err := c.Commit(ctx, "history-repo", "change", "relink source only", "tester", nil, nil, nil, false)
	require.NoError(t, err)

	// Diverge the destination so merging must apply the binding change through catalog history.
	require.NoError(t, c.CreateEntry(ctx, "history-repo", "main", DBEntry{Path: "unrelated", PhysicalAddress: "data/unrelated", AddressType: AddressTypeRelative, CreationDate: time.Now()}))
	_, err = c.Commit(ctx, "history-repo", "main", "destination change", "tester", nil, nil, nil, false)
	require.NoError(t, err)
	merged, err := c.Merge(ctx, "history-repo", "main", "change", "tester", "merge source binding", nil, "")
	require.NoError(t, err)
	require.NoError(t, c.Revert(ctx, "history-repo", "main", RevertParams{Reference: relinked.Reference, Committer: "tester"}))

	for _, test := range []struct{ ref, storageID string }{
		{base.Reference, "source-a"},
		{relinked.Reference, "source-b"},
		{merged, "source-b"},
		{"main", "source-a"},
		{"change", "source-b"},
	} {
		got, err := c.GetEntry(ctx, "history-repo", test.ref, "object", GetEntryParams{})
		require.NoError(t, err)
		require.Equal(t, test.storageID, got.StorageID, "ref %s", test.ref)
		require.Equal(t, entry.PhysicalAddress, got.PhysicalAddress)
		require.Equal(t, AddressTypeFull, got.AddressType)
	}
	_, err = c.GetEntry(ctx, "history-repo", "main", "unrelated", GetEntryParams{})
	require.NoError(t, err, "reverting the source binding must preserve the destination's other change")
}

func TestStorageBindingMetadataUpdatePreservesRepresentation(t *testing.T) {
	t.Parallel()
	for _, sourceID := range []string{"", "external"} {
		t.Run(sourceID, func(t *testing.T) {
			store := newBindingTestStore()
			c := &Catalog{Store: store}
			entry := DBEntry{Path: "object", StorageID: sourceID, PhysicalAddress: "s3://bucket/key", AddressType: AddressTypeFull, CreationDate: time.Now(), ContentType: "text/plain"}
			require.NoError(t, c.CreateEntry(t.Context(), "repo", "main", entry))
			require.NoError(t, c.UpdateEntryUserMetadata(t.Context(), "repo", "main", "object", map[string]string{"changed": "yes"}))
			got, err := c.GetEntry(t.Context(), "repo", "main", "object", GetEntryParams{})
			require.NoError(t, err)
			require.Equal(t, sourceID, got.StorageID)
			require.Equal(t, AddressTypeFull, got.AddressType)
			require.Equal(t, entry.PhysicalAddress, got.PhysicalAddress)
			require.Equal(t, map[string]string{"changed": "yes"}, map[string]string(got.Metadata))
		})
	}
}

func TestStoredBindingsAfterRepositoryRelocation(t *testing.T) {
	t.Parallel()
	store := newBindingTestStore()
	original := &Catalog{Store: store}
	for _, entry := range []DBEntry{
		{Path: "managed", PhysicalAddress: "data/object", AddressType: AddressTypeRelative},
		{Path: "external", PhysicalAddress: "gs://source/object", AddressType: AddressTypeFull, StorageID: "source"},
	} {
		require.NoError(t, original.CreateEntry(t.Context(), "repo", "main", entry))
	}
	// Raw restore retains the serialized values and changes only repository context.
	store.repository = &graveler.RepositoryRecord{RepositoryID: "relocated", Repository: &graveler.Repository{StorageID: "destination", StorageNamespace: "s3://relocated-bucket/repo", DefaultBranchID: "main"}}
	restored := &Catalog{Store: store}
	for _, test := range []struct{ path, storageID, address string }{
		{"managed", "destination", "s3://relocated-bucket/repo/data/object"},
		{"external", "source", "gs://source/object"},
	} {
		entry, err := restored.GetEntry(t.Context(), "relocated", "main", test.path, GetEntryParams{})
		require.NoError(t, err)
		obj, err := block.NewObjectPointer(entry.StorageID, "destination", "s3://relocated-bucket/repo", entry.PhysicalAddress, entry.AddressType.ToIdentifierType())
		require.NoError(t, err)
		require.Equal(t, test.storageID, obj.StorageID)
		address, err := obj.FullAddress()
		require.NoError(t, err)
		require.Equal(t, test.address, address)
	}
}

func TestWriteRangeStorageBindingNormalAndSkipped(t *testing.T) {
	t.Parallel()
	store := newBindingTestStore()
	walker := &bindingTestWalker{
		entries: []block.ObjectStoreEntry{{RelativeKey: "normal", Address: "gs://source/normal", ETag: "n", Mtime: time.Now()}},
		skipped: []block.ObjectStoreEntry{{RelativeKey: "skipped", Address: "gs://source/skipped", ETag: "s", Mtime: time.Now()}},
	}
	adapter := &bindingTestAdapter{getWalker: func(storageID string, _ block.WalkerOptions) (block.Walker, error) {
		require.Equal(t, "gcs-source", storageID)
		return walker, nil
	}}
	c := &Catalog{Store: store, BlockAdapter: adapter}
	_, mark, err := c.WriteRange(t.Context(), "repo", WriteRangeRequest{StorageID: "gcs-source", SourceURI: "gs://source/", Prepend: "dest/"})
	require.NoError(t, err)
	require.NotEmpty(t, mark.StagingToken)
	require.Len(t, store.rangeValues, 1)
	require.Len(t, store.staged, 1)
	for _, value := range []graveler.ValueRecord{store.rangeValues[0], store.staged[0]} {
		entry, err := ValueToEntry(value.Value)
		require.NoError(t, err)
		require.Equal(t, "gcs-source", entry.StorageId)
		require.Equal(t, Entry_FULL, entry.AddressType)
		require.True(t, strings.HasPrefix(entry.Address, "gs://source/"))
	}
}

func TestImportTemporarySerializationPreservesStorageBinding(t *testing.T) {
	t.Parallel()
	db, err := pebble.Open(t.TempDir(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	importer := &Import{db: db}
	for _, entry := range []EntryRecord{
		{Path: "a", Entry: &Entry{Address: "s3://bucket/a", AddressType: Entry_FULL, StorageId: "s3-source"}},
		{Path: "b", Entry: &Entry{Address: "gs://bucket/b", AddressType: Entry_FULL, StorageId: "gcs-source"}},
	} {
		require.NoError(t, importer.set(entry))
	}
	it, err := importer.NewItr()
	require.NoError(t, err)
	defer it.Close()
	var ids []string
	for it.Next() {
		entry, err := ValueToEntry(it.Value().Value)
		require.NoError(t, err)
		ids = append(ids, entry.StorageId)
	}
	require.NoError(t, it.Err())
	require.Equal(t, []string{"s3-source", "gcs-source"}, ids)
}

func TestActionsSourceUsesFullSourceBinding(t *testing.T) {
	t.Parallel()
	store := newBindingTestStore()
	store.values["_lakefs_actions/action.yaml"] = MustEntryToValue(&Entry{Address: "gs://actions-bucket/action.yaml", AddressType: Entry_FULL, StorageId: "actions-source"})
	adapter := &bindingTestAdapter{get: func(_ context.Context, obj block.ObjectPointer) (io.ReadCloser, error) {
		require.Equal(t, "actions-source", obj.StorageID)
		require.Equal(t, block.IdentifierTypeFull, obj.IdentifierType)
		require.Equal(t, "gs://actions-bucket/action.yaml", obj.Identifier)
		return io.NopCloser(strings.NewReader("name: linked action")), nil
	}}
	source := NewActionsSource(&Catalog{Store: store, BlockAdapter: adapter})
	got, err := source.Load(t.Context(), graveler.HookRecord{Repository: store.repository, SourceRef: "main"}, "_lakefs_actions/action.yaml")
	require.NoError(t, err)
	require.Equal(t, "name: linked action", string(got))
}

func TestPhysicalCopyClearsSourceBinding(t *testing.T) {
	t.Parallel()
	store := newBindingTestStore()
	store.values["source"] = MustEntryToValue(&Entry{Address: "s3://external/object", AddressType: Entry_FULL, StorageId: "home", LastModified: timestamppb.Now()})
	adapter := &bindingTestAdapter{copy: func(_ context.Context, source, destination block.ObjectPointer) error {
		require.Equal(t, "home", source.StorageID)
		require.Equal(t, block.IdentifierTypeFull, source.IdentifierType)
		require.Equal(t, "s3://external/object", source.Identifier)
		require.Equal(t, "home", destination.StorageID)
		require.Equal(t, block.IdentifierTypeRelative, destination.IdentifierType)
		return nil
	}}
	c := &Catalog{Store: store, BlockAdapter: adapter, PathProvider: upload.NewPathPartitionProvider()}
	got, err := c.CopyEntry(t.Context(), "repo", "main", "source", "repo", "main", "destination", false, nil)
	require.NoError(t, err)
	require.Empty(t, got.StorageID)
	require.Equal(t, AddressTypeRelative, got.AddressType)
	stored, err := ValueToEntry(store.values["destination"])
	require.NoError(t, err)
	require.Empty(t, stored.StorageId)
}

func TestGCStorageBindingOwnership(t *testing.T) {
	t.Parallel()
	store := newBindingTestStore()
	store.diffs = []*graveler.Diff{
		bindingTestDiff("1", "", "data/managed", Entry_RELATIVE),
		bindingTestDiff("2", "alias", "s3://bucket/repo/data/alias", Entry_FULL),
		bindingTestDiff("3", "foreign", "s3://bucket/repo/data/foreign", Entry_FULL),
		bindingTestDiff("4", "home", "s3://bucket/repo/outside-data", Entry_FULL),
	}
	ownership := storageOwnership{
		"home":    {provider: "s3", service: "one"},
		"alias":   {provider: "s3", service: "one"},
		"foreign": {provider: "s3", service: "two"},
	}
	var output bytes.Buffer
	mark, hasData, err := gcWriteUncommitted(t.Context(), store, store.repository, ownership, NewUncommittedWriter(&output), nil, "run", 1<<20, 0)
	require.NoError(t, err)
	require.Nil(t, mark)
	require.True(t, hasData)
	file := buffer.NewBufferFileFromBytes(output.Bytes())
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	pr, err := reader.NewParquetReader(file, new(UncommittedParquetObject), 1)
	require.NoError(t, err)
	defer pr.ReadStop()
	rows := make([]*UncommittedParquetObject, pr.GetNumRows())
	require.NoError(t, pr.Read(&rows))
	var addresses []string
	for _, row := range rows {
		addresses = append(addresses, row.PhysicalAddress)
	}
	require.Equal(t, []string{"data/managed", "data/alias", "outside-data"}, addresses)

	// Unknown context after valid records must fail the page, never publish a partial retention set.
	store.diffs = append(store.diffs, bindingTestDiff("5", "removed", "s3://bucket/repo/data/unknown", Entry_FULL))
	output.Reset()
	mark, hasData, err = gcWriteUncommitted(t.Context(), store, store.repository, ownership, NewUncommittedWriter(&output), nil, "run", 1<<20, 0)
	require.ErrorIs(t, err, config.ErrNoStorageConfig)
	require.Nil(t, mark)
	require.False(t, hasData)
}

func TestGCLaterPageRejectsUnknownOwnership(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		store := newBindingTestStore()
		store.branchDiffs = map[graveler.BranchID][]*graveler.Diff{
			"first":  {bindingTestDiff("1", "", "data/managed", Entry_RELATIVE)},
			"second": {bindingTestDiff("2", "removed", "s3://bucket/repo/data/unknown", Entry_FULL)},
		}
		store.afterBranch = func(branch graveler.BranchID) {
			if branch == "first" {
				time.Sleep(time.Second)
			}
		}
		var firstPage bytes.Buffer
		mark, hasData, err := gcWriteUncommitted(t.Context(), store, store.repository, nil, NewUncommittedWriter(&firstPage), nil, "run", 1<<20, time.Millisecond)
		require.NoError(t, err)
		require.True(t, hasData)
		require.NotNil(t, mark)
		require.Equal(t, graveler.BranchID("second"), mark.BranchID)
		var nextPage bytes.Buffer
		nextMark, hasData, err := gcWriteUncommitted(t.Context(), store, store.repository, nil, NewUncommittedWriter(&nextPage), mark, "run", 1<<20, time.Millisecond)
		require.ErrorIs(t, err, config.ErrNoStorageConfig)
		require.Nil(t, nextMark)
		require.False(t, hasData, "the caller must invalidate the run, including the prior successful page")
	})
}

func TestGCRejectsForeignRelativeBinding(t *testing.T) {
	t.Parallel()
	store := newBindingTestStore()
	store.diffs = []*graveler.Diff{bindingTestDiff("1", "foreign", "data/object", Entry_RELATIVE)}
	_, hasData, err := gcWriteUncommitted(t.Context(), store, store.repository, nil, NewUncommittedWriter(io.Discard), nil, "run", 1<<20, 0)
	require.ErrorIs(t, err, block.ErrInvalidAddress)
	require.False(t, hasData)
}

func bindingTestDiff(key, storageID, address string, addressType Entry_AddressType) *graveler.Diff {
	return &graveler.Diff{Key: []byte(key), Type: graveler.DiffTypeAdded, Value: MustEntryToValue(&Entry{StorageId: storageID, Address: address, AddressType: addressType, LastModified: timestamppb.Now()})}
}

type bindingTestStore struct {
	Store
	repository          *graveler.RepositoryRecord
	values              map[string]*graveler.Value
	rangeValues, staged []graveler.ValueRecord
	branchDiffs         map[graveler.BranchID][]*graveler.Diff
	afterBranch         func(graveler.BranchID)
	diffs               []*graveler.Diff
}

func newBindingTestStore() *bindingTestStore {
	return &bindingTestStore{repository: &graveler.RepositoryRecord{RepositoryID: "repo", Repository: &graveler.Repository{StorageID: "home", StorageNamespace: "s3://bucket/repo", DefaultBranchID: "main"}}, values: make(map[string]*graveler.Value)}
}
func (s *bindingTestStore) GetRepository(context.Context, graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	return s.repository, nil
}
func (s *bindingTestStore) Get(_ context.Context, _ *graveler.RepositoryRecord, _ graveler.Ref, key graveler.Key, _ ...graveler.GetOptionsFunc) (*graveler.Value, error) {
	return s.values[string(key)], nil
}
func (s *bindingTestStore) Set(_ context.Context, _ *graveler.RepositoryRecord, _ graveler.BranchID, key graveler.Key, value graveler.Value, _ ...graveler.SetOptionsFunc) error {
	s.values[string(key)] = &value
	return nil
}
func (s *bindingTestStore) Update(_ context.Context, _ *graveler.RepositoryRecord, _ graveler.BranchID, key graveler.Key, update graveler.ValueUpdateFunc, _ ...graveler.SetOptionsFunc) error {
	value, err := update(s.values[string(key)])
	if err == nil {
		s.values[string(key)] = value
	}
	return err
}
func (s *bindingTestStore) WriteRange(_ context.Context, _ *graveler.RepositoryRecord, it graveler.ValueIterator, _ ...graveler.SetOptionsFunc) (*graveler.RangeInfo, error) {
	for it.Next() {
		s.rangeValues = append(s.rangeValues, *it.Value())
	}
	return &graveler.RangeInfo{}, it.Err()
}
func (s *bindingTestStore) StageObject(_ context.Context, _ string, value graveler.ValueRecord) error {
	s.staged = append(s.staged, value)
	return nil
}
func (s *bindingTestStore) ListBranches(context.Context, *graveler.RepositoryRecord, ...graveler.ListOptionsFunc) (graveler.BranchIterator, error) {
	if s.branchDiffs == nil {
		return gtest.NewFakeBranchIterator([]*graveler.BranchRecord{{BranchID: "main", Branch: &graveler.Branch{}}}), nil
	}
	var branches []*graveler.BranchRecord
	for branchID := range s.branchDiffs {
		branches = append(branches, &graveler.BranchRecord{BranchID: branchID, Branch: &graveler.Branch{}})
	}
	sort.Slice(branches, func(i, j int) bool { return branches[i].BranchID < branches[j].BranchID })
	return gtest.NewFakeBranchIterator(branches), nil
}
func (s *bindingTestStore) DiffUncommitted(_ context.Context, _ *graveler.RepositoryRecord, branchID graveler.BranchID) (graveler.DiffIterator, error) {
	if s.branchDiffs == nil {
		return &bindingTestDiffIterator{diffs: s.diffs, index: -1}, nil
	}
	return &bindingTestDiffIterator{diffs: s.branchDiffs[branchID], index: -1, done: func() {
		if s.afterBranch != nil {
			s.afterBranch(branchID)
		}
	}}, nil
}

type bindingTestDiffIterator struct {
	diffs []*graveler.Diff
	index int
	done  func()
}

func (i *bindingTestDiffIterator) Next() bool {
	i.index++
	if i.index < len(i.diffs) {
		return true
	}
	if i.done != nil {
		i.done()
		i.done = nil
	}
	return false
}
func (i *bindingTestDiffIterator) Value() *graveler.Diff { return i.diffs[i.index] }
func (i *bindingTestDiffIterator) SeekGE(key graveler.Key) {
	i.index = -1
	for i.index+1 < len(i.diffs) && bytes.Compare(i.diffs[i.index+1].Key, key) < 0 {
		i.index++
	}
}
func (i *bindingTestDiffIterator) Err() error { return nil }
func (i *bindingTestDiffIterator) Close()     {}

type bindingTestAdapter struct {
	block.Adapter
	getWalker func(string, block.WalkerOptions) (block.Walker, error)
	get       func(context.Context, block.ObjectPointer) (io.ReadCloser, error)
	copy      func(context.Context, block.ObjectPointer, block.ObjectPointer) error
}

func (a *bindingTestAdapter) GetWalker(id string, options block.WalkerOptions) (block.Walker, error) {
	return a.getWalker(id, options)
}
func (a *bindingTestAdapter) Get(ctx context.Context, obj block.ObjectPointer) (io.ReadCloser, error) {
	return a.get(ctx, obj)
}
func (a *bindingTestAdapter) Copy(ctx context.Context, source, destination block.ObjectPointer) error {
	return a.copy(ctx, source, destination)
}

type bindingTestWalker struct{ entries, skipped []block.ObjectStoreEntry }

func (w *bindingTestWalker) Walk(_ context.Context, _ *url.URL, _ block.WalkOptions, visit func(block.ObjectStoreEntry) error) error {
	for _, entry := range w.entries {
		if err := visit(entry); err != nil {
			return err
		}
	}
	return nil
}
func (w *bindingTestWalker) Marker() block.Mark                          { return block.Mark{} }
func (w *bindingTestWalker) GetSkippedEntries() []block.ObjectStoreEntry { return w.skipped }

func TestGCStorageBindingConfiguredAliases(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, namespace, address string
		home, source             config.AdapterConfig
		err                      error
	}{
		{
			name: "private and presigning endpoints", namespace: "s3://bucket/repo", address: "s3://bucket/repo/data/object",
			home: s3OwnershipStorage("https://private.example", "https://public.example"), source: s3OwnershipStorage("https://public.example", ""),
		},
		{
			name: "default IPv6 endpoint port", namespace: "s3://bucket/repo", address: "s3://bucket/repo/data/object",
			home: s3OwnershipStorage("https://[2001:db8::1]:443", ""), source: s3OwnershipStorage("https://[2001:db8::1]", ""),
		},
		{
			name: "S3 reads gs locator", namespace: "s3://bucket/repo", address: "gs://bucket/repo/data/object",
			home: s3OwnershipStorage("https://private.example", ""), source: s3OwnershipStorage("https://private.example", ""),
		},
		{
			name: "S3 reads https locator", namespace: "s3://bucket/repo", address: "https://bucket/repo/data/object",
			home: s3OwnershipStorage("https://private.example", ""), source: s3OwnershipStorage("https://private.example", ""),
		},
		{
			name: "Azure account hostname case", namespace: "https://account.blob.core.windows.net/container/repo", address: "https://ACCOUNT.blob.core.windows.net/container/repo/data/object",
			home:   &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "azure", Azure: &config.BlockstoreAzure{}}},
			source: &config.BlockstoreStorage{BlockstoreConfig: config.BlockstoreConfig{Type: "azure", Azure: &config.BlockstoreAzure{}}},
		},
		{
			name: "unknown presigning identity fails page", namespace: "s3://bucket/repo", address: "s3://bucket/repo/data/object",
			home: s3OwnershipStorage("https://private.example", "not-an-endpoint"), source: s3OwnershipStorage("https://public.example", ""), err: ErrUnknownStorageOwnership,
		},
		{
			name: "unsupported source scheme fails page", namespace: "s3://bucket/repo", address: "ftp://bucket/repo/data/object",
			home: s3OwnershipStorage("https://private.example", ""), source: s3OwnershipStorage("https://private.example", ""), err: block.ErrInvalidAddress,
		},
		{
			name: "malformed source locator fails page", namespace: "s3://bucket/repo", address: "s3://%invalid/repo/data/object",
			home: s3OwnershipStorage("https://private.example", ""), source: s3OwnershipStorage("https://private.example", ""), err: block.ErrInvalidAddress,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newBindingTestStore()
			store.repository.StorageNamespace = graveler.StorageNamespace(test.namespace)
			store.diffs = []*graveler.Diff{bindingTestDiff("object", "alias", test.address, Entry_FULL)}
			ownership := newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{"home": test.home, "alias": test.source}})
			var output bytes.Buffer
			mark, hasData, err := gcWriteUncommitted(t.Context(), store, store.repository, ownership, NewUncommittedWriter(&output), nil, "run", 1<<20, 0)
			require.ErrorIs(t, err, test.err)
			require.Nil(t, mark)
			if test.err != nil {
				require.False(t, hasData)
				return
			}
			require.True(t, hasData, "an alias must emit managed-object retention")
			file := buffer.NewBufferFileFromBytes(output.Bytes())
			t.Cleanup(func() { require.NoError(t, file.Close()) })
			pr, err := reader.NewParquetReader(file, new(UncommittedParquetObject), 1)
			require.NoError(t, err)
			defer pr.ReadStop()
			require.EqualValues(t, 1, pr.GetNumRows())
			rows := make([]*UncommittedParquetObject, 1)
			require.NoError(t, pr.Read(&rows))
			require.Equal(t, "data/object", rows[0].PhysicalAddress)
		})
	}
}
