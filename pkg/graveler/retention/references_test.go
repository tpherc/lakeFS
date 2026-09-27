package retention

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/testutil"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/kv/kvparams"
)

var errReferencesTest = errors.New("injected retained history read failure")

type referencesTestCommitIterator struct {
	graveler.CommitIterator
	failure error
	closed  bool
}

func (i *referencesTestCommitIterator) Err() error { return i.failure }
func (i *referencesTestCommitIterator) Close()     { i.closed = true; i.CommitIterator.Close() }

type referencesTestBranchIterator struct {
	graveler.BranchIterator
	failure error
}

func (i *referencesTestBranchIterator) Err() error { return i.failure }

type referencesTestRefs struct {
	GCRefManager
	commits  []*graveler.CommitRecord
	branches []*graveler.BranchRecord
	dangling []*graveler.CommitRecord
	failure  string
	list     *referencesTestCommitIterator
}

func (r *referencesTestRefs) ListCommits(context.Context, *graveler.RepositoryRecord) (graveler.CommitIterator, error) {
	r.list = &referencesTestCommitIterator{CommitIterator: testutil.NewFakeCommitIterator(r.commits)}
	if r.failure == "commits" {
		r.list.failure = errReferencesTest
	}
	return r.list, nil
}
func (r *referencesTestRefs) GCBranchIterator(context.Context, *graveler.RepositoryRecord) (graveler.BranchIterator, error) {
	it := &referencesTestBranchIterator{BranchIterator: testutil.NewFakeBranchIterator(r.branches)}
	if r.failure == "branches" {
		it.failure = errReferencesTest
	}
	return it, nil
}
func (r *referencesTestRefs) GCCommitIterator(context.Context, *graveler.RepositoryRecord) (graveler.CommitIterator, error) {
	it := &referencesTestCommitIterator{CommitIterator: testutil.NewFakeCommitIterator(r.dangling)}
	if r.failure == "dangling" {
		it.failure = errReferencesTest
	}
	return it, nil
}
func (r *referencesTestRefs) GetCommit(_ context.Context, _ *graveler.RepositoryRecord, id graveler.CommitID) (*graveler.Commit, error) {
	for _, commit := range r.commits {
		if commit.CommitID == id {
			return commit.Commit, nil
		}
	}
	return nil, graveler.ErrNotFound
}

func TestForEachRetainedCommitNoPolicyKeepsAllKnownHistory(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	refs := &referencesTestRefs{commits: []*graveler.CommitRecord{
		{CommitID: "old-unreachable", Commit: &graveler.Commit{CreationDate: now.AddDate(-20, 0, 0), MetaRangeID: "mr-old"}},
		{CommitID: "head", Commit: &graveler.Commit{CreationDate: now, MetaRangeID: "mr-head"}},
	}}
	var ids []graveler.CommitID
	err := ForEachRetainedCommit(t.Context(), refs, &graveler.RepositoryRecord{}, nil, now, func(id graveler.CommitID, _ graveler.MetaRangeID) error { ids = append(ids, id); return nil })
	require.NoError(t, err)
	require.ElementsMatch(t, []graveler.CommitID{"old-unreachable", "head"}, ids)
	require.True(t, refs.list.closed)
	refs.failure = "commits"
	err = ForEachRetainedCommit(t.Context(), refs, &graveler.RepositoryRecord{}, nil, now, func(graveler.CommitID, graveler.MetaRangeID) error { return nil })
	require.ErrorIs(t, err, errReferencesTest, "terminal page error must invalidate even an otherwise complete list")
	require.True(t, refs.list.closed)
}

func TestForEachRetainedCommitUsesCapturedPolicyTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	commit := func(id string, age int, parents ...graveler.CommitID) *graveler.CommitRecord {
		return &graveler.CommitRecord{CommitID: graveler.CommitID(id), Commit: &graveler.Commit{Version: graveler.CurrentCommitVersion, CreationDate: now.AddDate(0, 0, -age), Parents: parents, MetaRangeID: graveler.MetaRangeID("mr-" + id)}}
	}
	refs := &referencesTestRefs{
		commits:  []*graveler.CommitRecord{commit("head", 1, "boundary"), commit("boundary", 8, "expired"), commit("expired", 10), commit("dangling", 1), commit("dangling-old", 20)},
		branches: []*graveler.BranchRecord{{BranchID: "main", Branch: &graveler.Branch{CommitID: "head"}}},
		dangling: []*graveler.CommitRecord{commit("dangling", 1), commit("dangling-old", 20)},
	}
	var ids []graveler.CommitID
	err := ForEachRetainedCommit(t.Context(), refs, &graveler.RepositoryRecord{}, &graveler.GarbageCollectionRules{DefaultRetentionDays: 5}, now, func(id graveler.CommitID, _ graveler.MetaRangeID) error { ids = append(ids, id); return nil })
	require.NoError(t, err)
	require.ElementsMatch(t, []graveler.CommitID{"head", "boundary", "dangling"}, ids, "retain branch head, first beyond window and young dangling commits at acceptance time")
}

func TestForEachRetainedCommitPolicyReadFailures(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"commits", "branches", "dangling", "missing parent", "visitor"} {
		t.Run(failure, func(t *testing.T) {
			refs := &referencesTestRefs{failure: failure}
			if failure == "missing parent" || failure == "visitor" {
				head := &graveler.CommitRecord{CommitID: "head", Commit: &graveler.Commit{CreationDate: time.Now(), MetaRangeID: "mr-head"}}
				if failure == "missing parent" {
					head.Parents = []graveler.CommitID{"missing"}
				}
				refs.commits = []*graveler.CommitRecord{head}
				refs.branches = []*graveler.BranchRecord{{BranchID: "main", Branch: &graveler.Branch{CommitID: "head"}}}
			}
			err := ForEachRetainedCommit(t.Context(), refs, &graveler.RepositoryRecord{}, &graveler.GarbageCollectionRules{DefaultRetentionDays: 1}, time.Now(), func(graveler.CommitID, graveler.MetaRangeID) error {
				if failure == "visitor" {
					return errReferencesTest
				}
				return nil
			})
			if failure == "missing parent" {
				require.ErrorIs(t, err, graveler.ErrNotFound)
			} else {
				require.ErrorIs(t, err, errReferencesTest)
			}
		})
	}
}

func TestCommitsMapPropagatesIteratorErrorAndCleanup(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store, err := kv.Open(ctx, kvparams.Config{Type: "mem"})
	require.NoError(t, err)
	defer store.Close()
	refs := &referencesTestRefs{failure: "commits"}
	getter := &RepositoryCommitGetterAdapter{RefManager: refs, Repository: &graveler.RepositoryRecord{}}
	_, err = NewCommitsMap(ctx, getter, store, nil)
	require.ErrorIs(t, err, errReferencesTest)
	refs.failure = ""
	cleaned := false
	cache, err := NewCommitsMap(ctx, getter, store, func() { cleaned = true })
	require.NoError(t, err)
	cache.Close()
	require.True(t, cleaned, "successful creation must retain its cleanup callback")
}

func TestForEachRetainedCommitCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	refs := &referencesTestRefs{commits: []*graveler.CommitRecord{{CommitID: "one", Commit: &graveler.Commit{}}, {CommitID: "two", Commit: &graveler.Commit{}}}}
	visits := 0
	err := ForEachRetainedCommit(ctx, refs, &graveler.RepositoryRecord{}, nil, time.Now(), func(graveler.CommitID, graveler.MetaRangeID) error { visits++; cancel(); return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, visits)
	require.True(t, refs.list.closed)
}
