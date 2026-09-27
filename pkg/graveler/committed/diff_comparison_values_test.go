package committed_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/committed"
	"github.com/treeverse/lakefs/pkg/graveler/testutil"
)

func comparisonValue(identity string) *graveler.Value {
	if identity == "" {
		return nil
	}
	return &graveler.Value{Identity: []byte(identity), Data: []byte("metadata-" + identity)}
}

func comparisonRange(id string, values ...*graveler.ValueRecord) *testutil.FakeIterator {
	it := testutil.NewFakeIterator()
	if len(values) > 0 {
		it.AddRange(&committed.Range{ID: committed.ID(id), MinKey: committed.Key(values[0].Key), MaxKey: committed.Key(values[len(values)-1].Key)})
		it.AddValueRecords(values...)
	}
	return it
}

type comparedValuesRangeCase struct {
	name                string
	left, right         map[string]string
	leftKeys, rightKeys [][]string
}

func TestDiffRetainsComparedValuesAcrossRanges(t *testing.T) {
	t.Parallel()
	for _, test := range []comparedValuesRangeCase{
		{"overlap", map[string]string{"a": "old-a", "b": "old-b"}, map[string]string{"b": "new-b", "c": "new-c"}, [][]string{{"a", "b"}}, [][]string{{"b", "c"}}},
		{"disjoint ranges", map[string]string{"a": "old-a", "b": "old-b"}, map[string]string{"c": "new-c", "d": "new-d"}, [][]string{{"a", "b"}}, [][]string{{"c", "d"}}},
		{"whole removed range", map[string]string{"a": "old-a", "b": "old-b"}, nil, [][]string{{"a", "b"}}, nil},
		{"whole added range", nil, map[string]string{"a": "new-a", "b": "new-b"}, nil, [][]string{{"a", "b"}}},
		{"matching bounds", map[string]string{"a": "old-a", "b": "old-b"}, map[string]string{"a": "new-a", "b": "new-b"}, [][]string{{"a", "b"}}, [][]string{{"a", "b"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			testDiffRetainedRangeValues(t, test)
		})
	}
}

func testDiffRetainedRangeValues(t *testing.T, test comparedValuesRangeCase) {
	t.Helper()
	left, right := buildComparedValueRanges(test.leftKeys, test.left), buildComparedValueRanges(test.rightKeys, test.right)
	it := committed.NewDiffIterator(t.Context(), left, right)
	defer it.Close()
	var diffs []*graveler.Diff
	for it.Next() {
		if diff, _ := it.Value(); diff != nil {
			diffs = append(diffs, diff)
		}
	}
	require.NoError(t, it.Err())
	// Inputs may be reused after advancement or closure; retained values own their bytes.
	for _, input := range []*testutil.FakeIterator{left, right} {
		for _, record := range input.RV {
			if record.V != nil {
				clear(record.V.Data)
				clear(record.V.Identity)
			}
		}
	}
	keys := make(map[string]bool)
	for _, diff := range diffs {
		key := string(diff.Key)
		keys[key] = true
		require.Equal(t, comparisonValue(test.left[key]), diff.LeftValue, key)
		wantValue := test.right[key]
		if wantValue == "" {
			wantValue = test.left[key]
		}
		require.Equal(t, comparisonValue(wantValue), diff.Value, key)
		require.Nil(t, diff.BaseValue)
	}
	for key := range test.left {
		require.True(t, keys[key], key)
	}
	for key := range test.right {
		require.True(t, keys[key], key)
	}
}

type comparisonConflictCase struct {
	name, base, dest, source string
	typ                      graveler.DiffType
}

func TestCompareRetainsAllConflictParticipants(t *testing.T) {
	t.Parallel()
	for _, test := range []comparisonConflictCase{
		{"add add", "", "dest", "source", graveler.DiffTypeChanged},
		{"modify modify", "base", "dest", "source", graveler.DiffTypeChanged},
		{"modify delete", "base", "dest", "", graveler.DiffTypeRemoved},
		{"delete modify", "base", "", "source", graveler.DiffTypeAdded},
	} {
		t.Run(test.name, func(t *testing.T) {
			testCompareConflictParticipants(t, test)
		})
	}
}

func testCompareConflictParticipants(t *testing.T, test comparisonConflictCase) {
	t.Helper()
	value := test.source
	if value == "" {
		value = test.dest
	}
	diff := graveler.Diff{Type: test.typ, Key: []byte("key"), Value: comparisonValue(value), LeftValue: comparisonValue(test.dest), LeftIdentity: []byte(test.dest)}
	base := comparisonRange("base")
	if test.base != "" {
		base = comparisonRange("base", &graveler.ValueRecord{Key: []byte("key"), Value: comparisonValue(test.base)})
	}
	it := committed.NewCompareValueIterator(t.Context(), committed.NewDiffIteratorWrapper(testutil.NewDiffIter([]graveler.Diff{diff})), base)
	defer it.Close()
	require.True(t, it.Next())
	got := it.Value()
	require.False(t, it.Next())
	require.NoError(t, it.Err())
	clear(diff.Value.Data)
	if diff.LeftValue != nil {
		clear(diff.LeftValue.Data)
	}
	for _, record := range base.RV {
		if record.V != nil {
			clear(record.V.Data)
		}
	}
	require.Equal(t, graveler.DiffTypeConflict, got.Type)
	require.Equal(t, comparisonValue(value), got.Value, "legacy removal conflict payload remains the destination")
	require.Equal(t, comparisonValue(test.dest), got.LeftValue)
	require.Equal(t, comparisonValue(test.base), got.BaseValue)
}

func TestCompareRejectsIncompleteComparedValues(t *testing.T) {
	t.Parallel()
	for _, diff := range []graveler.Diff{
		{Type: graveler.DiffTypeAdded},
		{Type: graveler.DiffTypeChanged, Value: comparisonValue("new")},
		{Type: graveler.DiffTypeChanged, LeftValue: comparisonValue("old")},
		{Type: graveler.DiffTypeRemoved, Value: comparisonValue("old")},
		{Type: graveler.DiffTypeRemoved, LeftValue: comparisonValue("old")},
	} {
		it := committed.NewCompareValueIterator(t.Context(), committed.NewDiffIteratorWrapper(testutil.NewDiffIter([]graveler.Diff{diff})), comparisonRange("empty"))
		require.False(t, it.Next())
		require.ErrorIs(t, it.Err(), graveler.ErrInvalidValue)
		it.Close()
	}
}

func TestComparePropagatesFailureAfterSkippingChange(t *testing.T) {
	t.Parallel()
	failure := errors.New("diff advancement failed")
	// A destination-only addition is skipped. The next diff read fails.
	input := testutil.NewDiffIter([]graveler.Diff{{Type: graveler.DiffTypeRemoved, Key: []byte("key"), Value: comparisonValue("old"), LeftValue: comparisonValue("old")}})
	input.SetErr(failure)
	it := committed.NewCompareValueIterator(t.Context(), committed.NewDiffIteratorWrapper(input), comparisonRange("empty"))
	defer it.Close()
	require.False(t, it.Next())
	require.ErrorIs(t, it.Err(), failure)
	require.Nil(t, it.Value())
}

func TestComparePropagatesBaseRangeAdvancementFailure(t *testing.T) {
	t.Parallel()
	failure := errors.New("base range advancement failed")
	base := comparisonRange("empty")
	base.SetErr(failure)
	diff := &testutil.FakeDiffIterator{}
	diff.AddRange(&committed.RangeDiff{Type: graveler.DiffTypeAdded, Range: &committed.Range{ID: "range", MinKey: []byte("key"), MaxKey: []byte("key")}})
	// FakeDiffIterator starts at index zero, so prepend its normal empty sentinel.
	diff.DRV = append([]testutil.DRV{{}}, diff.DRV...)
	it := committed.NewCompareIterator(t.Context(), diff, base)
	defer it.Close()
	require.False(t, it.Next())
	require.ErrorIs(t, it.Err(), failure)
}

func TestCompareChangedRangeRetainsIndividualConflictValues(t *testing.T) {
	t.Parallel()
	left := comparisonRange("left", &graveler.ValueRecord{Key: []byte("a"), Value: comparisonValue("old")})
	right := comparisonRange("right", &graveler.ValueRecord{Key: []byte("a"), Value: comparisonValue("new")})
	base := comparisonRange("base", &graveler.ValueRecord{Key: []byte("z"), Value: comparisonValue("unrelated")})
	it := committed.NewCompareValueIterator(t.Context(), committed.NewDiffIterator(t.Context(), left, right), base)
	defer it.Close()
	require.True(t, it.Next())
	require.Equal(t, graveler.DiffTypeConflict, it.Value().Type)
	require.Equal(t, comparisonValue("old"), it.Value().LeftValue)
	require.Equal(t, comparisonValue("new"), it.Value().Value)
	require.Nil(t, it.Value().BaseValue)
	require.False(t, it.Next())
	require.NoError(t, it.Err())
}

// Reuses the previous value's storage when advancing, as an iterator may do.
type advancingComparisonBase struct {
	committed.Iterator
	previous *graveler.ValueRecord
}

func (i *advancingComparisonBase) Next() bool {
	if i.previous != nil {
		clear(i.previous.Data)
	}
	return i.Iterator.Next()
}

func (i *advancingComparisonBase) Value() (*graveler.ValueRecord, *committed.Range) {
	value, rng := i.Iterator.Value()
	i.previous = value
	return value, rng
}

func TestCompareCapturesBaseBeforeAdvancingItsBuffer(t *testing.T) {
	t.Parallel()
	diff := graveler.Diff{Type: graveler.DiffTypeChanged, Key: []byte("key"), Value: comparisonValue("new"), LeftValue: comparisonValue("old"), LeftIdentity: []byte("old")}
	base := &advancingComparisonBase{Iterator: comparisonRange("base",
		&graveler.ValueRecord{Key: []byte("key"), Value: comparisonValue("base")},
		&graveler.ValueRecord{Key: []byte("later"), Value: comparisonValue("later")},
	)}
	it := committed.NewCompareValueIterator(t.Context(), committed.NewDiffIteratorWrapper(testutil.NewDiffIter([]graveler.Diff{diff})), base)
	defer it.Close()
	require.True(t, it.Next())
	require.Equal(t, comparisonValue("base"), it.Value().BaseValue)
	require.NoError(t, it.Err())
}

type failingDiffPrefetch struct {
	committed.Iterator
	failure   error
	readValue bool
	failed    bool
}

func (i *failingDiffPrefetch) Next() bool {
	if i.readValue {
		i.failed = true
		return false
	}
	return i.Iterator.Next()
}

func (i *failingDiffPrefetch) Value() (*graveler.ValueRecord, *committed.Range) {
	value, rng := i.Iterator.Value()
	if value != nil {
		i.readValue = true
	}
	return value, rng
}

func (i *failingDiffPrefetch) Err() error {
	if i.failed {
		return i.failure
	}
	return i.Iterator.Err()
}

func TestDiffRejectsPrefetchFailureBeforeEmittingChange(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, leftKey, rightKey string
		failLeft                bool
	}{
		{"changed", "a", "a", true},
		{"removed", "a", "b", true},
		{"added", "b", "a", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := errors.New("diff prefetch failed")
			var left committed.Iterator = comparisonRange("left",
				&graveler.ValueRecord{Key: []byte(test.leftKey), Value: comparisonValue("left")},
				&graveler.ValueRecord{Key: []byte("z"), Value: comparisonValue("left-tail")},
			)
			var right committed.Iterator = comparisonRange("right",
				&graveler.ValueRecord{Key: []byte(test.rightKey), Value: comparisonValue("right")},
				&graveler.ValueRecord{Key: []byte("z"), Value: comparisonValue("right-tail")},
			)
			if test.failLeft {
				left = &failingDiffPrefetch{Iterator: left, failure: failure}
			} else {
				right = &failingDiffPrefetch{Iterator: right, failure: failure}
			}
			it := committed.NewDiffIterator(t.Context(), left, right)
			defer it.Close()
			for it.Next() {
				value, _ := it.Value()
				require.Nil(t, value, "a prefetched failure must stop before a row can trigger a directory seek")
			}
			require.ErrorIs(t, it.Err(), failure)
			value, _ := it.Value()
			require.Nil(t, value)
		})
	}
}

func TestCompareRejectsMissingBaseValue(t *testing.T) {
	t.Parallel()
	base := comparisonRange("base", &graveler.ValueRecord{Key: []byte("key")})
	diff := graveler.Diff{Type: graveler.DiffTypeChanged, Key: []byte("key"), Value: comparisonValue("new"), LeftValue: comparisonValue("old"), LeftIdentity: []byte("old")}
	it := committed.NewCompareValueIterator(t.Context(), committed.NewDiffIteratorWrapper(testutil.NewDiffIter([]graveler.Diff{diff})), base)
	defer it.Close()
	require.False(t, it.Next())
	require.ErrorIs(t, it.Err(), graveler.ErrInvalidValue)
	require.Nil(t, it.Value())
}

func buildComparedValueRanges(keys [][]string, values map[string]string) *testutil.FakeIterator {
	ids := make([][]string, len(keys))
	for i, group := range keys {
		for _, key := range group {
			ids[i] = append(ids[i], values[key])
		}
	}
	it := newFakeMetaRangeIterator(keys, ids)
	for _, record := range it.RV {
		if record.V != nil {
			record.V.Data = []byte("metadata-" + string(record.V.Identity))
		}
	}
	return it
}
