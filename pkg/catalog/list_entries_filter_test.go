package catalog_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func listingRecords(classifications map[string]string) []*graveler.ValueRecord {
	paths := make([]string, 0, len(classifications))
	for path := range classifications {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	records := make([]*graveler.ValueRecord, 0, len(paths))
	for _, path := range paths {
		records = append(records, &graveler.ValueRecord{
			Key: graveler.Key(path),
			Value: catalog.MustEntryToValue(&catalog.Entry{
				Address:      "data/" + path,
				LastModified: timestamppb.New(time.Unix(1, 0)),
				Metadata:     map[string]string{"dcs:cls": classifications[path]},
			}),
		})
	}
	return records
}

func listingPaths(entries []*catalog.DBEntry) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

func TestCatalog_ListEntriesFilter(t *testing.T) {
	t.Parallel()
	records := listingRecords(map[string]string{
		"a-denied":          "S",
		"b-allowed":         "U",
		"d/denied":          "S",
		"p/a-denied":        "S",
		"p/b-allowed":       "U",
		"p/c-allowed":       "U",
		"p/d-denied":        "S",
		"p/hidden/a-denied": "S",
		"p/mixed/a-denied":  "S",
		"p/mixed/b-allowed": "U",
		"p/mixed/c-allowed": "U",
		"z-allowed":         "U",
	})
	for _, tt := range []struct {
		name      string
		prefix    string
		after     string
		delimiter string
		limit     int
		paths     []string
		hasMore   bool
	}{
		{name: "sparse page", limit: 2, paths: []string{"b-allowed", "p/b-allowed"}, hasMore: true},
		{name: "page after allowed", after: "p/b-allowed", limit: 2, paths: []string{"p/c-allowed", "p/mixed/b-allowed"}, hasMore: true},
		{name: "page after denied", after: "p/d-denied", limit: 2, paths: []string{"p/mixed/b-allowed", "p/mixed/c-allowed"}, hasMore: true},
		{name: "all denied", prefix: "d/", limit: 1, paths: []string{}},
		{name: "prefix and marker", prefix: "p/", after: "p/b-allowed", limit: 10, paths: []string{"p/c-allowed", "p/mixed/b-allowed", "p/mixed/c-allowed"}},
		{name: "marker before prefix", prefix: "p/", after: "a", limit: 1, paths: []string{"p/b-allowed"}, hasMore: true},
		{name: "marker past prefix", prefix: "p/", after: "z", limit: 10, paths: []string{}},
		{name: "delimiter excludes denied prefixes", delimiter: "/", limit: 10, paths: []string{"b-allowed", "p/", "z-allowed"}},
		{name: "delimiter within prefix", prefix: "p/", delimiter: "/", limit: 10, paths: []string{"p/b-allowed", "p/c-allowed", "p/mixed/"}},
		{name: "delimiter after prefix", after: "p/", delimiter: "/", limit: 10, paths: []string{"z-allowed"}},
		{name: "delimiter marker within prefix", after: "p/mixed/b-allowed", delimiter: "/", limit: 10, paths: []string{"z-allowed"}},
		{name: "nested delimiter marker", prefix: "p/", after: "p/mixed/b-allowed", delimiter: "/", limit: 10, paths: []string{}},
		{name: "zero limit with readable object", limit: 0, paths: []string{}, hasMore: true},
		{name: "zero limit with denied objects", prefix: "d/", limit: 0, paths: []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := &listingFilterStore{records: records}
			c := &catalog.Catalog{Store: store}
			filter := func(entry *catalog.DBEntry) (bool, error) {
				require.False(t, entry.CommonLevel, "the predicate must receive stored objects")
				require.True(t, strings.HasPrefix(entry.Path, tt.prefix), "prefix restriction must precede filtering")
				return entry.Metadata["dcs:cls"] == "U", nil
			}
			entries, more, err := c.ListEntries(t.Context(), "repo", "main", tt.prefix, tt.after, tt.delimiter, tt.limit, catalog.WithEntryFilter(filter))
			require.NoError(t, err)
			require.Equal(t, tt.paths, listingPaths(entries))
			require.Equal(t, tt.hasMore, more)
			require.Equal(t, 1, store.calls)
			require.Equal(t, 1, store.iterator.closes)
			for _, entry := range entries {
				if strings.HasSuffix(entry.Path, "/") {
					require.True(t, entry.CommonLevel)
					require.Empty(t, entry.Metadata)
				} else {
					require.Equal(t, "U", entry.Metadata["dcs:cls"])
				}
			}
		})
	}
}

func TestCatalog_ListEntriesFilterSkipsRemainingAdmittedPrefix(t *testing.T) {
	t.Parallel()
	store := &listingFilterStore{records: listingRecords(map[string]string{
		"directory/a-denied": "S", "directory/b-allowed": "U", "directory/c-denied": "S", "z": "U",
	})}
	c := &catalog.Catalog{Store: store}
	var checked []string
	entries, more, err := c.ListEntries(t.Context(), "repo", "main", "", "", "/", 10, catalog.WithEntryFilter(func(entry *catalog.DBEntry) (bool, error) {
		checked = append(checked, entry.Path)
		return entry.Metadata["dcs:cls"] == "U", nil
	}))
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, []string{"directory/", "z"}, listingPaths(entries))
	require.Equal(t, []string{"directory/a-denied", "directory/b-allowed", "z"}, checked)
}

func TestCatalog_ListEntriesFilterPaginationAcrossDeniedRuns(t *testing.T) {
	t.Parallel()
	classifications := make(map[string]string)
	var expected []string
	for i := range 653 {
		path := fmt.Sprintf("file%04d", i)
		classifications[path] = "S"
		if i >= 650 {
			classifications[path] = "U"
			expected = append(expected, path)
		}
	}
	store := &listingFilterStore{records: listingRecords(classifications)}
	c := &catalog.Catalog{Store: store}
	filter := catalog.WithEntryFilter(func(entry *catalog.DBEntry) (bool, error) {
		return entry.Metadata["dcs:cls"] == "U", nil
	})
	entries, more, err := c.ListEntries(t.Context(), "repo", "main", "", "", "", 2, filter)
	require.NoError(t, err)
	require.True(t, more)
	require.Equal(t, expected[:2], listingPaths(entries))
	require.Equal(t, 1, store.calls, "internal pages must use the same Store.List iterator")
	require.Greater(t, store.iterator.pages, 1)
	require.Equal(t, 1, store.iterator.closes)

	entries, more, err = c.ListEntries(t.Context(), "repo", "main", "", entries[len(entries)-1].Path, "", 2, filter)
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, expected[2:], listingPaths(entries))
	require.Equal(t, 2, store.calls, "a new API page opens its own listing")
	require.Equal(t, 1, store.iterator.closes)
}

func TestCatalog_ListEntriesFilterErrorsDiscardPartialResults(t *testing.T) {
	t.Parallel()
	failure := errors.New("listing failed")
	for _, source := range []string{"predicate", "iterator"} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			store := &listingFilterStore{records: listingRecords(map[string]string{"a": "U", "b": "U"})}
			if source == "iterator" {
				store.failAt = 1
				store.failure = failure
			}
			c := &catalog.Catalog{Store: store}
			filter := catalog.WithEntryFilter(func(entry *catalog.DBEntry) (bool, error) {
				if source == "predicate" && entry.Path == "b" {
					return false, failure
				}
				return true, nil
			})
			entries, more, err := c.ListEntries(t.Context(), "repo", "main", "", "", "", 1, filter)
			require.ErrorIs(t, err, failure)
			require.Nil(t, entries)
			require.False(t, more)
			require.Equal(t, 1, store.iterator.closes)
		})
	}
}

func TestCatalog_ListEntriesFilterCancellation(t *testing.T) {
	t.Parallel()
	for _, allowed := range []bool{false, true} {
		t.Run(fmt.Sprintf("allowed=%t", allowed), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := &listingFilterStore{records: listingRecords(map[string]string{"a": "U", "b": "U", "c": "U", "d": "U"})}
			c := &catalog.Catalog{Store: store}
			checks := 0
			entries, more, err := c.ListEntries(ctx, "repo", "main", "", "", "", 10, catalog.WithEntryFilter(func(_ *catalog.DBEntry) (bool, error) {
				checks++
				if checks == 3 {
					cancel()
				}
				return allowed, nil
			}))
			require.ErrorIs(t, err, context.Canceled)
			require.Nil(t, entries)
			require.False(t, more)
			require.Equal(t, 3, checks)
			require.Equal(t, 1, store.iterator.closes)
		})
	}
}

// listingFilterStore exposes page-sized batches through a single iterator, like
// the catalog's staging backend. The requested page size is not a total limit.
type listingFilterStore struct {
	catalog.FakeGraveler
	records  []*graveler.ValueRecord
	calls    int
	failAt   int
	failure  error
	iterator *listingFilterValueIterator
}

func (s *listingFilterStore) List(_ context.Context, _ *graveler.RepositoryRecord, _ graveler.Ref, batchSize int) (graveler.ValueIterator, error) {
	s.calls++
	s.iterator = &listingFilterValueIterator{
		FakeValueIterator: catalog.NewFakeValueIterator(s.records),
		batchSize:         batchSize,
		failAt:            s.failAt,
		failure:           s.failure,
	}
	return s.iterator, nil
}

type listingFilterValueIterator struct {
	*catalog.FakeValueIterator
	batchSize int
	pages     int
	closes    int
	failAt    int
	failure   error
	err       error
}

func (i *listingFilterValueIterator) Next() bool {
	if i.failure != nil && i.Index+1 == i.failAt {
		i.err = i.failure
		return false
	}
	if !i.FakeValueIterator.Next() {
		return false
	}
	if i.Index%i.batchSize == 0 {
		i.pages++
	}
	return true
}

func (i *listingFilterValueIterator) Err() error {
	return i.err
}

func (i *listingFilterValueIterator) Close() {
	i.closes++
}
