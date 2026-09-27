package graveler_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/testutil"
)

func retainedValue(identity string) *graveler.Value {
	return &graveler.Value{Identity: []byte(identity), Data: []byte("metadata-" + identity)}
}

func TestDiffCopyOwnsComparisonValues(t *testing.T) {
	t.Parallel()
	diff := &graveler.Diff{Type: graveler.DiffTypeConflict, Key: []byte("key"), Value: retainedValue("new"), LeftValue: retainedValue("old"), BaseValue: retainedValue("base"), LeftIdentity: []byte("old")}
	copied := diff.Copy()
	clear(diff.Key)
	clear(diff.LeftIdentity)
	for _, value := range []*graveler.Value{diff.Value, diff.LeftValue, diff.BaseValue} {
		clear(value.Data)
		clear(value.Identity)
	}
	require.Equal(t, []byte("key"), []byte(copied.Key))
	require.Equal(t, []byte("old"), copied.LeftIdentity)
	require.Equal(t, retainedValue("new"), copied.Value)
	require.Equal(t, retainedValue("old"), copied.LeftValue)
	require.Equal(t, retainedValue("base"), copied.BaseValue)
}

func TestUncommittedDiffRetainsHistoricalValues(t *testing.T) {
	t.Parallel()
	oldChange, oldDelete, newChange, added := retainedValue("old-change"), retainedValue("old-delete"), retainedValue("new-change"), retainedValue("added")
	committed := testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("change"), Value: oldChange}, {Key: []byte("delete"), Value: oldDelete}})
	staged := testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("add"), Value: added}, {Key: []byte("change"), Value: newChange}, {Key: []byte("delete")}})
	it := graveler.NewUncommittedDiffIterator(t.Context(), committed, staged)
	defer it.Close()
	var diffs []*graveler.Diff
	for it.Next() {
		diffs = append(diffs, it.Value())
	}
	require.NoError(t, it.Err())
	require.Len(t, diffs, 3)
	for _, value := range []*graveler.Value{oldChange, oldDelete, newChange, added} {
		clear(value.Data)
		clear(value.Identity)
	}
	require.Equal(t, retainedValue("added"), diffs[0].Value)
	require.Nil(t, diffs[0].LeftValue)
	require.Equal(t, retainedValue("new-change"), diffs[1].Value)
	require.Equal(t, retainedValue("old-change"), diffs[1].LeftValue)
	require.Nil(t, diffs[2].Value, "legacy uncommitted deletion payload remains a tombstone")
	require.Equal(t, retainedValue("old-delete"), diffs[2].LeftValue)
	for _, diff := range diffs {
		require.Nil(t, diff.LeftIdentity, "preserve legacy uncommitted identity field")
	}
}

type failingComparisonValues struct {
	graveler.ValueIterator
	exhausted bool
	failure   error
}

func (i *failingComparisonValues) Next() bool {
	if i.ValueIterator.Next() {
		return true
	}
	i.exhausted = true
	return false
}

func (i *failingComparisonValues) Err() error {
	if i.exhausted {
		return i.failure
	}
	return nil
}

func TestUncommittedDiffPropagatesStagingFailure(t *testing.T) {
	t.Parallel()
	failure := errors.New("staging advancement failed")
	for _, skip := range []bool{false, true} {
		var committed graveler.ValueIterator
		if skip {
			committed = testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("key"), Value: retainedValue("same")}})
		}
		staged := &failingComparisonValues{ValueIterator: testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("key"), Value: retainedValue("same")}}), failure: failure}
		it := graveler.NewUncommittedDiffIterator(t.Context(), committed, staged)
		if !skip {
			require.True(t, it.Next())
		}
		require.False(t, it.Next())
		require.ErrorIs(t, it.Err(), failure)
		require.Nil(t, it.Value())
		it.Close()
	}
}

func TestUncommittedDiffCancellationDuringSkippedChanges(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	it := graveler.NewUncommittedDiffIterator(ctx, nil, testutil.NewValueIteratorFake(nil))
	defer it.Close()
	require.False(t, it.Next())
	require.ErrorIs(t, it.Err(), context.Canceled)
}

func TestJoinedDiffSeekResetsChildrenAfterProgressAndExhaustion(t *testing.T) {
	t.Parallel()
	for _, exhaustFirst := range []bool{false, true} {
		left := graveler.NewUncommittedDiffIterator(t.Context(), nil, testutil.NewValueIteratorFake([]graveler.ValueRecord{
			{Key: []byte("a/one"), Value: retainedValue("a")}, {Key: []byte("b/one"), Value: retainedValue("b")},
		}))
		right := graveler.NewUncommittedDiffIterator(t.Context(), nil, testutil.NewValueIteratorFake([]graveler.ValueRecord{
			{Key: []byte("a/two"), Value: retainedValue("a2")}, {Key: []byte("c/one"), Value: retainedValue("c")},
		}))
		it := graveler.NewJoinedDiffIterator(left, right)
		require.True(t, it.Next())
		if exhaustFirst {
			for it.Next() {
			}
		}
		// Real uncommitted children clear Value on SeekGE. A stale joined state
		// would dereference that cleared Value, or retain an exhausted input.
		it.SeekGE([]byte("b/"))
		require.Nil(t, it.Value())
		var paths []string
		for it.Next() {
			paths = append(paths, string(it.Value().Key))
		}
		require.NoError(t, it.Err())
		require.Equal(t, []string{"b/one", "c/one"}, paths)
		it.SeekGE([]byte("a/"))
		require.True(t, it.Next())
		require.Equal(t, "a/one", string(it.Value().Key))
		it.Close()
	}
}

func TestCombinedDiffRetainsLeftDataBeforeStagingAdvances(t *testing.T) {
	t.Parallel()
	oldChange, oldDelete := retainedValue("old-change"), retainedValue("old-delete")
	newChange := retainedValue("new-change")
	left := testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("change"), Value: oldChange}, {Key: []byte("delete"), Value: oldDelete}})
	staged := testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("change"), Value: newChange}, {Key: []byte("delete")}})
	it := graveler.NewCombinedDiffIterator(testutil.NewDiffIter(nil), left, staged)
	defer it.Close()
	var diffs []*graveler.Diff
	for it.Next() {
		diffs = append(diffs, it.Value())
	}
	require.NoError(t, it.Err())
	require.Len(t, diffs, 2)
	clear(oldChange.Data)
	clear(oldDelete.Data)
	clear(newChange.Data)
	require.Equal(t, retainedValue("new-change"), diffs[0].Value)
	require.Equal(t, retainedValue("old-change"), diffs[0].LeftValue)
	require.Equal(t, retainedValue("old-delete"), diffs[1].Value)
	require.Equal(t, retainedValue("old-delete"), diffs[1].LeftValue)
}

func TestStagingDiffRejectsMissingCommittedValue(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"uncommitted", "combined"} {
		for _, change := range []string{"replacement", "deletion"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				// Nil values are valid staging tombstones, but cannot stand in for
				// an existing entry in the full committed baseline used by either producer.
				left := testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("key")}})
				var next *graveler.Value
				if change == "replacement" {
					next = retainedValue("new")
				}
				staged := testutil.NewValueIteratorFake([]graveler.ValueRecord{{Key: []byte("key"), Value: next}})
				var it graveler.DiffIterator
				if kind == "uncommitted" {
					it = graveler.NewUncommittedDiffIterator(t.Context(), left, staged)
				} else {
					it = graveler.NewCombinedDiffIterator(testutil.NewDiffIter(nil), left, staged)
				}
				defer it.Close()
				require.False(t, it.Next())
				require.ErrorIs(t, it.Err(), graveler.ErrInvalidValue)
				require.Nil(t, it.Value())
			})
		}
	}
}
