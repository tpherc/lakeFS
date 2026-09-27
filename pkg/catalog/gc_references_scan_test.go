package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/retention"
	gtest "github.com/treeverse/lakefs/pkg/graveler/testutil"
	"github.com/xitongsys/parquet-go-source/buffer"
	"github.com/xitongsys/parquet-go/reader"
	"github.com/xitongsys/parquet-go/source"
)

var errGCReferencesTest = errors.New("injected reference scan failure")

type gcReferencesScanStore struct {
	Store
	repositories   []*graveler.RepositoryRecord
	staging        map[graveler.RepositoryID][]*graveler.Diff
	committed      map[graveler.RepositoryID][]*graveler.ValueRecord
	events         []string
	failure        string
	postReads      map[graveler.RepositoryID]int
	commits        map[graveler.RepositoryID][]*graveler.CommitRecord
	committedByRef map[graveler.RepositoryID]map[graveler.Ref][]*graveler.ValueRecord
	policies       map[graveler.RepositoryID]*graveler.GarbageCollectionRules
	heads          map[graveler.RepositoryID][]*graveler.BranchRecord
	dangling       map[graveler.RepositoryID][]*graveler.CommitRecord
	afterStaging   func(graveler.RepositoryID, bool)
}

func (s *gcReferencesScanStore) GetRepository(_ context.Context, id graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	s.postReads[id]++
	if s.failure == "repository disappeared" && s.postReads[id] > 1 {
		return nil, graveler.ErrNotFound
	}
	for _, repo := range s.repositories {
		if repo.RepositoryID == id {
			return repo, nil
		}
	}
	return nil, graveler.ErrNotFound
}
func (s *gcReferencesScanStore) ListRepositories(context.Context) (graveler.RepositoryIterator, error) {
	return &gcReferencesRepoIterator{RepositoryIterator: NewFakeRepositoryIterator(s.repositories), failure: s.errorFor("repository iterator")}, nil
}
func (s *gcReferencesScanStore) ListBranches(_ context.Context, repo *graveler.RepositoryRecord, _ ...graveler.ListOptionsFunc) (graveler.BranchIterator, error) {
	s.events = append(s.events, string(repo.RepositoryID)+":branches")
	return &gcReferencesBranchIterator{BranchIterator: gtest.NewFakeBranchIterator([]*graveler.BranchRecord{{BranchID: "main", Branch: &graveler.Branch{}}}), failure: s.errorFor("branch iterator")}, nil
}
func (s *gcReferencesScanStore) DiffUncommitted(_ context.Context, repo *graveler.RepositoryRecord, _ graveler.BranchID) (graveler.DiffIterator, error) {
	s.events = append(s.events, string(repo.RepositoryID)+":staging")
	return &gcReferencesDiffIterator{DiffIterator: &FakeDiffIterator{Data: s.staging[repo.RepositoryID], Index: -1}, failure: s.errorFor("staging iterator"), afterClose: func(exhausted bool) {
		if s.afterStaging != nil {
			s.afterStaging(repo.RepositoryID, exhausted)
		}
	}}, nil
}
func (s *gcReferencesScanStore) GetGarbageCollectionRules(_ context.Context, repo *graveler.RepositoryRecord) (*graveler.GarbageCollectionRules, error) {
	s.events = append(s.events, string(repo.RepositoryID)+":policy")
	if s.failure == "policy" {
		return nil, errGCReferencesTest
	}
	if rules := s.policies[repo.RepositoryID]; rules != nil {
		return rules, nil
	}
	return nil, graveler.ErrNotFound
}
func (s *gcReferencesScanStore) List(_ context.Context, repo *graveler.RepositoryRecord, ref graveler.Ref, _ int) (graveler.ValueIterator, error) {
	s.events = append(s.events, string(repo.RepositoryID)+":commit:"+ref.String())
	values := s.committed[repo.RepositoryID]
	if s.committedByRef != nil {
		values = s.committedByRef[repo.RepositoryID][ref]
	}
	return &gcReferencesValueIterator{ValueIterator: NewFakeValueIterator(values), failure: s.errorFor("entry iterator")}, nil
}
func (s *gcReferencesScanStore) GCGetUncommittedLocation(repo *graveler.RepositoryRecord, run string) (string, error) {
	return string(repo.StorageNamespace) + "/_lakefs/retention/" + run, nil
}
func (s *gcReferencesScanStore) errorFor(point string) error {
	if s.failure == point {
		return errGCReferencesTest
	}
	return nil
}

type gcReferencesRepoIterator struct {
	graveler.RepositoryIterator
	failure error
}

func (i *gcReferencesRepoIterator) Err() error { return i.failure }

type gcReferencesBranchIterator struct {
	graveler.BranchIterator
	failure error
}

func (i *gcReferencesBranchIterator) Err() error { return i.failure }

type gcReferencesDiffIterator struct {
	graveler.DiffIterator
	failure    error
	exhausted  bool
	afterClose func(bool)
}

func (i *gcReferencesDiffIterator) Next() bool {
	ok := i.DiffIterator.Next()
	i.exhausted = !ok
	return ok
}
func (i *gcReferencesDiffIterator) Close() {
	i.DiffIterator.Close()
	if i.afterClose != nil {
		i.afterClose(i.exhausted)
	}
}
func (i *gcReferencesDiffIterator) Err() error { return i.failure }

type gcReferencesValueIterator struct {
	graveler.ValueIterator
	failure error
}

func (i *gcReferencesValueIterator) Err() error { return i.failure }

type gcReferencesCommitIterator struct {
	graveler.CommitIterator
	failure error
}

func (i *gcReferencesCommitIterator) Err() error { return i.failure }

type gcReferencesScanRefs struct {
	retention.GCRefManager
	store *gcReferencesScanStore
}

func (r *gcReferencesScanRefs) ListCommits(_ context.Context, repo *graveler.RepositoryRecord) (graveler.CommitIterator, error) {
	r.store.events = append(r.store.events, repo.RepositoryID.String()+":commit-roots")
	commits := r.store.commits[repo.RepositoryID]
	if r.store.commits == nil {
		commits = []*graveler.CommitRecord{
			{CommitID: "head", Commit: &graveler.Commit{MetaRangeID: "head-meta"}},
			{CommitID: "dangling", Commit: &graveler.Commit{MetaRangeID: "dangling-meta"}},
		}
	}
	return &gcReferencesCommitIterator{CommitIterator: gtest.NewFakeCommitIterator(commits), failure: r.store.errorFor("commit iterator")}, nil
}
func (r *gcReferencesScanRefs) GCBranchIterator(_ context.Context, repo *graveler.RepositoryRecord) (graveler.BranchIterator, error) {
	return gtest.NewFakeBranchIterator(r.store.heads[repo.RepositoryID]), nil
}
func (r *gcReferencesScanRefs) GCCommitIterator(_ context.Context, repo *graveler.RepositoryRecord) (graveler.CommitIterator, error) {
	return gtest.NewFakeCommitIterator(r.store.dangling[repo.RepositoryID]), nil
}
func (r *gcReferencesScanRefs) GetCommit(_ context.Context, repo *graveler.RepositoryRecord, id graveler.CommitID) (*graveler.Commit, error) {
	for _, record := range r.store.commits[repo.RepositoryID] {
		if record.CommitID == id {
			return record.Commit, nil
		}
	}
	return nil, graveler.ErrNotFound
}

type gcReferencesArtifactAdapter struct {
	block.Adapter
	objects   map[string][]byte
	pointers  []block.ObjectPointer
	failure   string
	afterPut  func()
	afterRead func(io.Reader)
}

func (a *gcReferencesArtifactAdapter) Put(_ context.Context, obj block.ObjectPointer, size int64, content io.Reader, _ block.PutOpts) (*block.PutResponse, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, errors.New("incorrect artifact length")
	}
	if a.failure == "part upload" && strings.HasSuffix(obj.Identifier, ".parquet") || a.failure == "manifest upload" && strings.HasSuffix(obj.Identifier, ".json") {
		return nil, errGCReferencesTest
	}
	a.objects[obj.Identifier] = data
	a.pointers = append(a.pointers, obj)
	if a.afterPut != nil {
		a.afterPut()
	}
	if a.afterRead != nil {
		a.afterRead(content)
	}
	return &block.PutResponse{}, nil
}

func newGCReferencesScanTest(t *testing.T) (*Catalog, *graveler.RepositoryRecord, *gcReferencesState, *gcReferencesScanStore, *gcReferencesArtifactAdapter) {
	t.Helper()
	c, owner, _, state := newGCReferencesTaskTest(t)
	owner.StorageNamespace = "s3://bucket/owner"
	state.Manifest.StorageNamespace = owner.StorageNamespace.String()
	state.Manifest.Target, _ = c.GCTargetDescriptor(gcReferencesRepository(owner))
	source := &graveler.RepositoryRecord{RepositoryID: "source", Repository: &graveler.Repository{InstanceUID: "source-uid", StorageID: "alias", StorageNamespace: "s3://bucket/source", ReadOnly: true}}
	c.ownership = newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{
		"test-storage": s3OwnershipStorage("https://objects.example", ""),
		"alias":        s3OwnershipStorage("https://objects.example", ""),
		"external":     s3OwnershipStorage("https://external.example", ""),
	}})
	state.Manifest.OwnershipFingerprint = c.GCOwnershipFingerprint()
	stage := func(id, address string, typ Entry_AddressType) *graveler.Diff {
		return bindingTestDiff("key", id, address, typ)
	}
	value := func(id, address string) *graveler.ValueRecord {
		return &graveler.ValueRecord{Key: []byte("key"), Value: stage(id, address, Entry_FULL).Value}
	}
	store := &gcReferencesScanStore{
		repositories: []*graveler.RepositoryRecord{owner, source}, postReads: make(map[graveler.RepositoryID]int),
		staging: map[graveler.RepositoryID][]*graveler.Diff{
			owner.RepositoryID:  {stage("", "data/owner-staged", Entry_RELATIVE)},
			source.RepositoryID: {stage("alias", "s3://bucket/owner/data/source-staged", Entry_FULL), {Type: graveler.DiffTypeRemoved}},
		},
		committed: map[graveler.RepositoryID][]*graveler.ValueRecord{
			owner.RepositoryID:  {value("test-storage", "s3://bucket/owner/data/owner-committed")},
			source.RepositoryID: {value("alias", "s3://bucket/owner/data/source-committed"), value("external", "s3://bucket/owner/data/external")},
		},
	}
	adapter := &gcReferencesArtifactAdapter{objects: make(map[string][]byte)}
	c.Store, c.BlockAdapter, c.gcReferencesRefs = store, adapter, &gcReferencesScanRefs{store: store}
	return c, owner, state, store, adapter
}

func TestGCReferencesScanCompleteManifest(t *testing.T) {
	t.Parallel()
	c, owner, state, store, adapter := newGCReferencesScanTest(t)
	progress := &gcReferencesProgress{}
	result, err := c.prepareGCReferenceArtifacts(t.Context(), owner, &state.Manifest, progress)
	require.NoError(t, err)
	require.NoError(t, validateGCReferencesResult(state.Manifest, result))
	require.Equal(t, []string{
		"test-repo:branches", "test-repo:staging", "test-repo:policy", "test-repo:commit-roots", "test-repo:commit:head", "test-repo:commit:dangling",
		"source:branches", "source:staging", "source:policy", "source:commit-roots", "source:commit:head", "source:commit:dangling",
	}, store.events, "every source reads staging before discovering retained commit roots")
	require.EqualValues(t, 2, state.Manifest.SourceCount)
	require.EqualValues(t, 4, state.Manifest.CommitCount)
	require.EqualValues(t, 8, state.Manifest.EntryCount)
	require.EqualValues(t, 6, state.Manifest.TotalRows)
	require.Equal(t, state.Manifest.EntryCount, progress.entries.Load())
	require.True(t, state.Manifest.Sources[1].NoPolicy, "read-only source with no policy still protects all commits")
	data := adapter.objects[result.ManifestLocation]
	require.Equal(t, result.ManifestSHA256, gcReferencesDigest(data))
	var decoded GCReferencesManifest
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, state.Manifest, decoded)
	require.Len(t, decoded.Parts, 1)
	part := decoded.Parts[0]
	bytes := adapter.objects[part.Location]
	require.Equal(t, part.SHA256, gcReferencesDigest(bytes))
	require.EqualValues(t, len(bytes), part.SizeBytes)
	file := buffer.NewBufferFileFromBytes(bytes)
	defer file.Close()
	parquet, err := reader.NewParquetReader(file, new(gcReferenceRow), 1)
	require.NoError(t, err)
	defer parquet.ReadStop()
	rows := make([]gcReferenceRow, parquet.GetNumRows())
	require.NoError(t, parquet.Read(&rows))
	addresses := make([]string, len(rows))
	for i, row := range rows {
		addresses[i] = row.PhysicalAddress
	}
	require.ElementsMatch(t, []string{"data/owner-staged", "data/owner-committed", "data/owner-committed", "data/source-staged", "data/source-committed", "data/source-committed"}, addresses)
	for _, pointer := range adapter.pointers {
		require.Equal(t, owner.StorageID.String(), pointer.StorageID)
		require.True(t, strings.HasPrefix(pointer.Identifier, owner.StorageNamespace.String()+"/"))
	}
}

func TestGCReferencesScanFailureNeverPublishesManifest(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"repository iterator", "branch iterator", "staging iterator", "commit iterator", "entry iterator", "policy", "repository disappeared", "part upload", "manifest upload", "unknown binding", "foreign relative", "malformed full"} {
		t.Run(failure, func(t *testing.T) {
			c, owner, state, store, adapter := newGCReferencesScanTest(t)
			store.failure, adapter.failure = failure, failure
			switch failure {
			case "unknown binding":
				store.staging["source"] = []*graveler.Diff{bindingTestDiff("bad", "missing", "s3://bucket/owner/data/key", Entry_FULL)}
			case "foreign relative":
				store.staging["source"] = []*graveler.Diff{bindingTestDiff("bad", "external", "data/key", Entry_RELATIVE)}
			case "malformed full":
				store.staging["source"] = []*graveler.Diff{bindingTestDiff("bad", "alias", "not a native address", Entry_FULL)}
			}
			result, err := c.prepareGCReferenceArtifacts(t.Context(), owner, &state.Manifest, &gcReferencesProgress{})
			require.Error(t, err)
			require.Nil(t, result)
			for key := range adapter.objects {
				require.False(t, strings.HasSuffix(key, "manifest.json"), "failed run published %s", key)
			}
		})
	}
}

func TestGCReferencesScanLateFailureInvalidatesEarlierParts(t *testing.T) {
	t.Parallel()
	for _, cancelAfterPart := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelAfterPart), func(t *testing.T) {
			c, owner, state, store, adapter := newGCReferencesScanTest(t)
			var diffs []*graveler.Diff
			for i := range gcReferencesPartRows + 1 {
				diffs = append(diffs, bindingTestDiff(fmt.Sprint(i), "", fmt.Sprintf("data/key-%d", i), Entry_RELATIVE))
			}
			store.staging[owner.RepositoryID] = diffs
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cancelAfterPart {
				adapter.afterPut = cancel
			} else {
				store.failure = "staging iterator"
			}
			result, err := c.prepareGCReferenceArtifacts(ctx, owner, &state.Manifest, &gcReferencesProgress{})
			require.Error(t, err)
			require.Nil(t, result)
			require.Len(t, adapter.objects, 1, "fixture must fail only after a complete first artifact")
			require.Len(t, state.Manifest.Parts, 1)
			for key := range adapter.objects {
				require.True(t, strings.HasSuffix(key, ".parquet"))
			}
		})
	}
}

func TestGCReferencesArtifactsPreserveNativeKeys(t *testing.T) {
	t.Parallel()
	c, owner, state, store, adapter := newGCReferencesScanTest(t)
	owner.StorageNamespace = "s3://bucket/owner//a%2Fb/../literal"
	state.Manifest.StorageNamespace = owner.StorageNamespace.String()
	var err error
	state.Manifest.Target, err = c.GCTargetDescriptor(gcReferencesRepository(owner))
	require.NoError(t, err)
	// The owner-relative staged entry ensures a part is written beneath this exact prefix.
	store.committed = nil
	result, err := c.prepareGCReferenceArtifacts(t.Context(), owner, &state.Manifest, &gcReferencesProgress{})
	require.NoError(t, err)
	require.NotEmpty(t, result.ManifestLocation)
	require.Len(t, adapter.objects, 2)
	for location := range adapter.objects {
		require.True(t, strings.HasPrefix(location, "s3://bucket/owner//a%2Fb/../literal/_lakefs/"), location)
	}
}

func gcReferencesTestAddresses(t *testing.T, manifest GCReferencesManifest, adapter *gcReferencesArtifactAdapter) []string {
	t.Helper()
	var addresses []string
	for _, part := range manifest.Parts {
		file := buffer.NewBufferFileFromBytes(adapter.objects[part.Location])
		pr, err := reader.NewParquetReader(file, new(gcReferenceRow), 1)
		require.NoError(t, err)
		rows := make([]gcReferenceRow, pr.GetNumRows())
		require.NoError(t, pr.Read(&rows))
		pr.ReadStop()
		require.NoError(t, file.Close())
		for _, row := range rows {
			addresses = append(addresses, row.PhysicalAddress)
		}
	}
	return addresses
}

func TestGCReferencesStagingCommittedBeforeRootCapture(t *testing.T) {
	t.Parallel()
	for _, failCommitRead := range []bool{false, true} {
		t.Run(fmt.Sprint(failCommitRead), func(t *testing.T) {
			c, owner, state, store, adapter := newGCReferencesScanTest(t)
			moved := bindingTestDiff("moving-key", "alias", "s3://bucket/owner/data/moved", Entry_FULL)
			store.staging = map[graveler.RepositoryID][]*graveler.Diff{"source": {moved}}
			store.commits = map[graveler.RepositoryID][]*graveler.CommitRecord{}
			store.committedByRef = map[graveler.RepositoryID]map[graveler.Ref][]*graveler.ValueRecord{}
			movedToCommit := false
			store.afterStaging = func(id graveler.RepositoryID, exhausted bool) {
				if id != "source" {
					return
				}
				require.True(t, exhausted, "commit must happen after every staged entry was consumed")
				delete(store.staging, id)
				store.commits[id] = []*graveler.CommitRecord{{CommitID: "new-commit", Commit: &graveler.Commit{MetaRangeID: "new-meta"}}}
				store.committedByRef[id] = map[graveler.Ref][]*graveler.ValueRecord{"new-commit": {{Key: moved.Key, Value: moved.Value}}}
				store.events = append(store.events, "source:commit-staged-entry")
				movedToCommit = true
				if failCommitRead {
					store.failure = "commit iterator"
				}
			}
			result, err := c.prepareGCReferenceArtifacts(t.Context(), owner, &state.Manifest, &gcReferencesProgress{})
			require.True(t, movedToCommit)
			require.Empty(t, store.staging["source"])
			if failCommitRead {
				require.ErrorIs(t, err, errGCReferencesTest)
				require.Nil(t, result)
				for location := range adapter.objects {
					require.False(t, strings.HasSuffix(location, "manifest.json"))
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)
			require.EqualValues(t, 1, state.Manifest.CommitCount, "the commit created at the staging boundary must be discovered")
			require.Equal(t, []string{"data/moved", "data/moved"}, gcReferencesTestAddresses(t, state.Manifest, adapter), "both staged and newly committed protection are observed")
			require.Contains(t, store.events, "source:commit:new-commit")
		})
	}
}

func TestGCReferencesRecentDeletionRetainsOldPredecessor(t *testing.T) {
	t.Parallel()
	for _, finitePolicy := range []bool{false, true} {
		t.Run(map[bool]string{false: "no policy", true: "finite policy"}[finitePolicy], func(t *testing.T) {
			c, owner, state, store, adapter := newGCReferencesScanTest(t)
			now := state.Manifest.StartedAt
			commit := func(id string, age int, parents ...graveler.CommitID) *graveler.CommitRecord {
				return &graveler.CommitRecord{CommitID: graveler.CommitID(id), Commit: &graveler.Commit{Version: graveler.CurrentCommitVersion, CreationDate: now.AddDate(0, 0, -age), Parents: parents, MetaRangeID: graveler.MetaRangeID("meta-" + id)}}
			}
			store.staging = nil
			store.commits = map[graveler.RepositoryID][]*graveler.CommitRecord{"source": {
				commit("deletion", 1, "old-version"), commit("old-version", 30, "obsolete"), commit("obsolete", 45), commit("dangling", 2), commit("unreachable-old", 20),
			}}
			store.heads = map[graveler.RepositoryID][]*graveler.BranchRecord{"source": {{BranchID: "main", Branch: &graveler.Branch{CommitID: "deletion"}}}}
			store.dangling = map[graveler.RepositoryID][]*graveler.CommitRecord{"source": {commit("dangling", 2), commit("unreachable-old", 20)}}
			store.committedByRef = map[graveler.RepositoryID]map[graveler.Ref][]*graveler.ValueRecord{"source": {}}
			for _, id := range []string{"old-version", "obsolete", "dangling", "unreachable-old"} {
				value := bindingTestDiff(id, "alias", "s3://bucket/owner/data/"+id, Entry_FULL).Value
				store.committedByRef["source"][graveler.Ref(id)] = []*graveler.ValueRecord{{Key: []byte(id), Value: value}}
			}
			if finitePolicy {
				store.policies = map[graveler.RepositoryID]*graveler.GarbageCollectionRules{"source": {DefaultRetentionDays: 5}}
			}
			result, err := c.prepareGCReferenceArtifacts(t.Context(), owner, &state.Manifest, &gcReferencesProgress{})
			require.NoError(t, err)
			require.NotNil(t, result)
			got := gcReferencesTestAddresses(t, state.Manifest, adapter)
			require.Contains(t, got, "data/old-version", "a recent deletion protects the 30-day-old previous object version")
			if finitePolicy {
				require.ElementsMatch(t, []string{"data/old-version", "data/dangling"}, got)
				require.EqualValues(t, 3, state.Manifest.CommitCount)
			} else {
				require.ElementsMatch(t, []string{"data/old-version", "data/obsolete", "data/dangling", "data/unreachable-old"}, got)
				require.EqualValues(t, 5, state.Manifest.CommitCount)
			}
		})
	}
}

type gcReferencesFailParquetFile struct {
	source.ParquetFile
	writes int
}

func (f *gcReferencesFailParquetFile) Write([]byte) (int, error) {
	f.writes++
	return 0, errGCReferencesTest
}

func TestGCReferencesParquetFinalizationFailure(t *testing.T) {
	t.Parallel()
	c, owner, state, _, adapter := newGCReferencesScanTest(t)
	var brokenPart *gcReferencePartWriter
	var failingFile *gcReferencesFailParquetFile
	createPart := func() (*gcReferencePartWriter, error) {
		var err error
		brokenPart, err = newGCReferencePartWriter()
		require.NoError(t, err)
		failingFile = &gcReferencesFailParquetFile{ParquetFile: brokenPart.parquet.PFile}
		brokenPart.parquet.PFile = failingFile
		return brokenPart, nil
	}
	result, err := c.prepareGCReferenceArtifactsWithWriter(t.Context(), owner, &state.Manifest, &gcReferencesProgress{}, createPart)
	require.ErrorIs(t, err, errGCReferencesTest)
	require.Nil(t, result)
	require.NotNil(t, brokenPart)
	require.EqualValues(t, 6, brokenPart.rows, "all owned rows must be buffered before finalization attempts physical writes")
	require.Equal(t, 1, failingFile.writes)
	require.Empty(t, adapter.objects, "failed Parquet finalization must not upload any artifact or manifest")
	require.Empty(t, state.Manifest.Parts)
	_, err = os.Stat(brokenPart.file.Name())
	require.ErrorIs(t, err, os.ErrNotExist, "failed part must release its temporary file")
}

func TestGCReferencesPartCloseFailure(t *testing.T) {
	t.Parallel()
	c, owner, state, _, adapter := newGCReferencesScanTest(t)
	adapter.afterRead = func(content io.Reader) {
		file, ok := content.(*os.File)
		require.True(t, ok, "fault must occur only after the completed Parquet file is consumed")
		require.NoError(t, file.Close())
	}
	result, err := c.prepareGCReferenceArtifacts(t.Context(), owner, &state.Manifest, &gcReferencesProgress{})
	require.ErrorIs(t, err, os.ErrClosed)
	require.ErrorContains(t, err, "close reference part")
	require.Nil(t, result)
	require.Len(t, adapter.objects, 1, "part upload succeeds before the close failure")
	for location := range adapter.objects {
		require.True(t, strings.HasSuffix(location, ".parquet"), "close failure must prevent manifest publication")
	}
	require.Empty(t, state.Manifest.Parts)
}
