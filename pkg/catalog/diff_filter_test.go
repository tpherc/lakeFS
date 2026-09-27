package catalog_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	gtest "github.com/treeverse/lakefs/pkg/graveler/testutil"
	"github.com/treeverse/lakefs/pkg/permissions"
)

func diffRecords(classes map[string]string) []graveler.Diff {
	var diffs []graveler.Diff
	for _, record := range listingRecords(classes) {
		diffs = append(diffs, graveler.Diff{Key: record.Key, Value: record.Value, Type: graveler.DiffTypeAdded})
	}
	return diffs
}

func diffPaths(diffs catalog.Differences) []string {
	paths := make([]string, 0, len(diffs))
	for _, diff := range diffs {
		paths = append(paths, diff.Path)
	}
	return paths
}

// Seeking clears Value, matching the committed/uncommitted iterator contract.
type filteredDiffIterator struct {
	diffs   []graveler.Diff
	next    int
	value   *graveler.Diff
	closes  int
	failAt  int
	failure error
	err     error
}

func (i *filteredDiffIterator) Next() bool {
	i.value = nil
	if i.err != nil {
		return false
	}
	if i.failure != nil && i.next == i.failAt {
		i.err = i.failure
		return false
	}
	if i.next >= len(i.diffs) {
		return false
	}
	i.value = &i.diffs[i.next]
	i.next++
	return true
}
func (i *filteredDiffIterator) SeekGE(key graveler.Key) {
	i.value = nil
	i.next, _ = slices.BinarySearchFunc(i.diffs, key, func(diff graveler.Diff, key graveler.Key) int { return bytes.Compare(diff.Key, key) })
}
func (i *filteredDiffIterator) Value() *graveler.Diff { return i.value }
func (i *filteredDiffIterator) Err() error            { return i.err }
func (i *filteredDiffIterator) Close()                { i.closes++ }

func diffCatalog(iter *filteredDiffIterator) *catalog.Catalog {
	return &catalog.Catalog{Store: &catalog.FakeGraveler{DiffIteratorFactory: func() graveler.DiffIterator { return iter }}}
}

func listFilteredDiff(ctx context.Context, c *catalog.Catalog, mode string, params catalog.DiffParams, opts ...catalog.DiffOptionsFunc) (catalog.Differences, bool, error) {
	switch mode {
	case "two-dot":
		return c.Diff(ctx, "repo", "left", "right", params, opts...)
	case "three-dot":
		return c.Compare(ctx, "repo", "left", "right", params, opts...)
	default:
		return c.DiffUncommitted(ctx, "repo", "main", params.Prefix, params.Delimiter, params.Limit, params.After, opts...)
	}
}

func TestCatalogDiffFilterPagination(t *testing.T) {
	t.Parallel()
	records := diffRecords(map[string]string{
		"a-hidden/file": "TS", "b-visible": "U", "p/a-hidden": "TS", "p/b-visible": "U", "p/c-visible": "U",
		"p/hidden/file": "TS", "p/mixed/a-hidden": "TS", "p/mixed/b-visible": "U", "p/mixed/c-hidden": "TS", "z-hidden": "TS",
	})
	for _, mode := range []string{"two-dot", "three-dot", "uncommitted"} {
		for _, tc := range []struct {
			name   string
			params catalog.DiffParams
			paths  []string
			more   bool
		}{
			{"full page", catalog.DiffParams{Limit: 2}, []string{"b-visible", "p/b-visible"}, true},
			{"next page", catalog.DiffParams{Limit: 2, After: "p/b-visible"}, []string{"p/c-visible", "p/mixed/b-visible"}, false},
			{"prefix", catalog.DiffParams{Limit: 10, Prefix: "p/", After: "p/b-visible"}, []string{"p/c-visible", "p/mixed/b-visible"}, false},
			{"before prefix", catalog.DiffParams{Limit: 1, Prefix: "p/", After: "a"}, []string{"p/b-visible"}, true},
			{"past prefix", catalog.DiffParams{Limit: 1, Prefix: "p/", After: "z"}, []string{}, false},
			{"all hidden", catalog.DiffParams{Limit: 1, Prefix: "a-hidden/"}, []string{}, false},
			{"directories", catalog.DiffParams{Limit: 10, Delimiter: "/"}, []string{"b-visible", "p/"}, false},
			{"nested directories", catalog.DiffParams{Limit: 10, Prefix: "p/", Delimiter: "/"}, []string{"p/b-visible", "p/c-visible", "p/mixed/"}, false},
			{"directory next page", catalog.DiffParams{Limit: 1, Delimiter: "/", After: "p/"}, []string{}, false},
			{"zero visible", catalog.DiffParams{Limit: 0}, []string{}, true},
			{"zero hidden", catalog.DiffParams{Limit: 0, Prefix: "a-hidden/"}, []string{}, false},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				iter := &filteredDiffIterator{diffs: records}
				diffs, more, err := listFilteredDiff(t.Context(), diffCatalog(iter), mode, tc.params, catalog.WithDiffFilter(func(diff *catalog.EntryDiff) (bool, error) {
					require.True(t, strings.HasPrefix(diff.Path.String(), tc.params.Prefix), "restrict prefix before invoking filter")
					require.NotEqual(t, tc.params.After, diff.Path.String())
					return diff.Entry.Metadata["dcs:cls"] == "U", nil
				}))
				require.NoError(t, err)
				require.Equal(t, tc.paths, diffPaths(diffs))
				require.Equal(t, tc.more, more)
				require.Equal(t, 1, iter.closes)
				for _, diff := range diffs {
					if diff.CommonLevel {
						require.Equal(t, catalog.DifferenceTypePrefixChanged, diff.Type)
						require.Empty(t, diff.Metadata)
					}
				}
			})
		}
	}
}

func TestCatalogDiffFilterStopsAtPrefixAndAdmittedDirectory(t *testing.T) {
	t.Parallel()
	iter := &filteredDiffIterator{diffs: diffRecords(map[string]string{
		"p/a/hidden": "TS", "p/a/visible": "U", "p/a/z": "TS", "p/b": "U", "q/outside": "TS", "r/outside": "TS",
	})}
	var checked []string
	diffs, more, err := listFilteredDiff(t.Context(), diffCatalog(iter), "two-dot", catalog.DiffParams{Limit: 10, Prefix: "p/", Delimiter: "/"}, catalog.WithDiffFilter(func(diff *catalog.EntryDiff) (bool, error) {
		checked = append(checked, diff.Path.String())
		return diff.Entry.Metadata["dcs:cls"] == "U", nil
	}))
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, []string{"p/a/", "p/b"}, diffPaths(diffs))
	require.Equal(t, []string{"p/a/hidden", "p/a/visible", "p/b"}, checked)
	require.Equal(t, 5, iter.next, "one prefix lookahead is enough; rejected rows outside prefix must not be scanned")
}

func TestCatalogDiffFilterLongDeniedRuns(t *testing.T) {
	t.Parallel()
	classes := make(map[string]string)
	for n := range 650 {
		classes[fmt.Sprintf("file%04d", n)] = "TS"
	}
	classes["visible-a"] = "U"
	classes["visible-b"] = "U"
	classes["visible-c"] = "U"
	classes["z-hidden"] = "TS"
	records := diffRecords(classes)
	var got []string
	after := ""
	for {
		iter := &filteredDiffIterator{diffs: records}
		diffs, more, err := listFilteredDiff(t.Context(), diffCatalog(iter), "uncommitted", catalog.DiffParams{Limit: 2, After: after}, catalog.WithDiffFilter(func(diff *catalog.EntryDiff) (bool, error) { return diff.Entry.Metadata["dcs:cls"] == "U", nil }))
		require.NoError(t, err)
		got = append(got, diffPaths(diffs)...)
		require.Equal(t, 1, iter.closes)
		if !more {
			break
		}
		require.Len(t, diffs, 2)
		after = diffs[len(diffs)-1].Path
	}
	require.Equal(t, []string{"visible-a", "visible-b", "visible-c"}, got)
}

func TestCatalogDiffFilterFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("diff failed")
	for _, mode := range []string{"two-dot", "three-dot", "uncommitted"} {
		for _, source := range []string{"filter", "iterator", "legacy decode", "left decode", "base decode", "cancel allow", "cancel deny"} {
			t.Run(mode+"/"+source, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				records := diffRecords(map[string]string{"a": "U", "b": "U"})
				iter := &filteredDiffIterator{diffs: records}
				if source == "iterator" {
					iter.failure = failure
					iter.failAt = 1
				}
				corrupt := &graveler.Value{Data: []byte{0xff}}
				switch source {
				case "legacy decode":
					records[1].Value = corrupt
				case "left decode":
					records[1].LeftValue = corrupt
				case "base decode":
					records[1].BaseValue = corrupt
				}
				diffs, more, err := listFilteredDiff(ctx, diffCatalog(iter), mode, catalog.DiffParams{Limit: 1}, catalog.WithDiffFilter(func(diff *catalog.EntryDiff) (bool, error) {
					if diff.Path == "b" {
						switch source {
						case "filter":
							return false, failure
						case "cancel allow":
							cancel()
							return true, nil
						case "cancel deny":
							cancel()
							return false, nil
						}
					}
					return true, nil
				}))
				require.Error(t, err)
				if source == "filter" || source == "iterator" {
					require.ErrorIs(t, err, failure)
				}
				if strings.HasPrefix(source, "cancel") {
					require.ErrorIs(t, err, context.Canceled)
				}
				require.Nil(t, diffs)
				require.False(t, more)
				require.Equal(t, 1, iter.closes)
			})
		}
	}
}

func TestCatalogDiffWithoutFilterPreservesLegacySideDecoding(t *testing.T) {
	t.Parallel()
	records := diffRecords(map[string]string{"a": "U"})
	records[0].LeftValue = &graveler.Value{Data: []byte{0xff}}
	records[0].BaseValue = &graveler.Value{Data: []byte{0xff}}
	iter := &filteredDiffIterator{diffs: records}
	diffs, more, err := listFilteredDiff(t.Context(), diffCatalog(iter), "two-dot", catalog.DiffParams{Limit: 10})
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, []string{"a"}, diffPaths(diffs))
	require.Equal(t, "U", diffs[0].Metadata["dcs:cls"])
}

type diffAuthorizerFunc func(context.Context, *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error)

func (f diffAuthorizerFunc) Authorize(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	return f(ctx, req)
}

func TestDiffPermissionFilterVersions(t *testing.T) {
	t.Parallel()
	entry := func(cls string) *catalog.Entry { return &catalog.Entry{Metadata: map[string]string{"dcs:cls": cls}} }
	policies := []*model.Policy{{Statement: model.Statements{{Effect: model.StatementEffectAllow, Action: []string{permissions.ReadObjectAction}, Resource: "*", Condition: map[string]map[string][]string{"StringEquals": {"lakefs:ObjectMetadata/dcs:cls": {"U"}}}}}}}
	var calls int
	authorizer := diffAuthorizerFunc(func(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
		calls++
		require.Equal(t, "alice", req.Username)
		require.Equal(t, "192.0.2.1", req.ClientIP)
		for _, node := range req.RequiredPermissions.Nodes {
			require.Equal(t, permissions.ReadObjectAction, node.Permission.Action)
			require.Equal(t, permissions.ObjectArn("repo", "file"), node.Permission.Resource)
		}
		result := auth.CheckPermissions(ctx, req.RequiredPermissions, req.Username, policies, &auth.MissingPermissions{})
		return &auth.AuthorizationResponse{Allowed: result == auth.CheckAllow}, nil
	})
	var options catalog.DiffOptions
	catalog.WithDiffPermissionFilter(t.Context(), authorizer, "alice", "repo", "192.0.2.1")(&options)
	for _, tc := range []struct {
		name    string
		diff    catalog.EntryDiff
		allowed bool
		invalid bool
	}{
		{"added readable", catalog.EntryDiff{Type: graveler.DiffTypeAdded, Entry: entry("U")}, true, false},
		{"added hidden", catalog.EntryDiff{Type: graveler.DiffTypeAdded, Entry: entry("TS")}, false, false},
		{"historical deletion", catalog.EntryDiff{Type: graveler.DiffTypeRemoved, LeftEntry: entry("U")}, true, false},
		{"hidden deletion", catalog.EntryDiff{Type: graveler.DiffTypeRemoved, LeftEntry: entry("TS")}, false, false},
		{"both readable", catalog.EntryDiff{Type: graveler.DiffTypeChanged, LeftEntry: entry("U"), Entry: entry("U")}, true, false},
		{"upgrade", catalog.EntryDiff{Type: graveler.DiffTypeChanged, LeftEntry: entry("U"), Entry: entry("TS")}, false, false},
		{"downgrade", catalog.EntryDiff{Type: graveler.DiffTypeChanged, LeftEntry: entry("TS"), Entry: entry("U")}, false, false},
		{"hidden base", catalog.EntryDiff{Type: graveler.DiffTypeConflict, LeftEntry: entry("U"), Entry: entry("U"), BaseEntry: entry("TS")}, false, false},
		{"hidden destination", catalog.EntryDiff{Type: graveler.DiffTypeConflict, LeftEntry: entry("TS"), Entry: entry("U"), BaseEntry: entry("U")}, false, false},
		{"hidden source", catalog.EntryDiff{Type: graveler.DiffTypeConflict, LeftEntry: entry("U"), Entry: entry("TS"), BaseEntry: entry("U")}, false, false},
		{"readable conflict", catalog.EntryDiff{Type: graveler.DiffTypeConflict, LeftEntry: entry("U"), Entry: entry("U"), BaseEntry: entry("U")}, true, false},
		{"add add absent base", catalog.EntryDiff{Type: graveler.DiffTypeConflict, LeftEntry: entry("U"), Entry: entry("U")}, true, false},
		{"delete modify absent destination", catalog.EntryDiff{Type: graveler.DiffTypeConflict, Entry: entry("U"), BaseEntry: entry("U")}, true, false},
		{"existing empty metadata", catalog.EntryDiff{Type: graveler.DiffTypeAdded, Entry: &catalog.Entry{}}, false, false},
		{"missing new", catalog.EntryDiff{Type: graveler.DiffTypeAdded}, false, true},
		{"missing old", catalog.EntryDiff{Type: graveler.DiffTypeRemoved, Entry: entry("U")}, false, true},
		{"missing changed old", catalog.EntryDiff{Type: graveler.DiffTypeChanged, Entry: entry("U")}, false, true},
		{"empty conflict", catalog.EntryDiff{Type: graveler.DiffTypeConflict}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.diff.Path = "file"
			before := calls
			allowed, err := options.FilterFunc(&tc.diff)
			require.Equal(t, tc.allowed, allowed)
			if tc.invalid {
				require.ErrorIs(t, err, catalog.ErrMissingDiffEntry)
				require.Equal(t, before, calls)
			} else {
				require.NoError(t, err)
				require.Equal(t, before+1, calls)
			}
		})
	}
}

func TestDiffPermissionFilterErrors(t *testing.T) {
	t.Parallel()
	failure := errors.New("authorizer unavailable")
	for _, tc := range []struct {
		name     string
		response *auth.AuthorizationResponse
		err      error
		wantErr  error
	}{
		{"nil response", nil, nil, auth.ErrInvalidRequest},
		{"call failure", nil, failure, failure},
		{"unexpected response error", &auth.AuthorizationResponse{Allowed: true, Error: failure}, nil, failure},
		{"denial", &auth.AuthorizationResponse{Error: auth.ErrInsufficientPermissions}, nil, nil},
		{"contradictory denial", &auth.AuthorizationResponse{Allowed: true, Error: auth.ErrInsufficientPermissions}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var options catalog.DiffOptions
			catalog.WithDiffPermissionFilter(t.Context(), diffAuthorizerFunc(func(context.Context, *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
				return tc.response, tc.err
			}), "alice", "repo", "")(&options)
			allowed, err := options.FilterFunc(&catalog.EntryDiff{Type: graveler.DiffTypeAdded, Path: "file", Entry: &catalog.Entry{}})
			require.False(t, allowed)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// Exercise actual Graveler compacted-state composition through catalog filtering
// and delimiter seeks. Managers supply immutable records in place of storage I/O.
func TestCatalogDiffCompactedUncommittedFilteringAndDirectories(t *testing.T) {
	t.Parallel()
	for _, stagedClasses := range []map[string]string{
		{"a-dir/a-staged": "U", "c-dir/staged": "U", "d-hidden/staged": "TS"},
		{"a-dir/a-staged": "U"},
		{},
	} {
		t.Run(fmt.Sprint(len(stagedClasses))+" staged", func(t *testing.T) {
			test := gtest.InitGravelerTest(t)
			repo := &graveler.RepositoryRecord{RepositoryID: "repo", Repository: &graveler.Repository{StorageNamespace: "mem://repo"}}
			branch := &graveler.Branch{CommitID: "commit", StagingToken: "staging", CompactedBaseMetaRangeID: "compacted"}
			test.RefManager.EXPECT().GetRepository(gomock.Any(), graveler.RepositoryID("repo")).Return(repo, nil).AnyTimes()
			test.RefManager.EXPECT().GetBranch(gomock.Any(), repo, graveler.BranchID("main")).Return(branch, nil).AnyTimes()
			test.RefManager.EXPECT().GetCommit(gomock.Any(), repo, graveler.CommitID("commit")).Return(&graveler.Commit{MetaRangeID: "base"}, nil).AnyTimes()
			test.StagingManager.EXPECT().List(gomock.Any(), graveler.StagingToken("staging"), 0).DoAndReturn(func(context.Context, graveler.StagingToken, int) graveler.ValueIterator {
				return catalog.NewFakeValueIterator(listingRecords(stagedClasses))
			}).AnyTimes()
			test.CommittedManager.EXPECT().List(gomock.Any(), repo.StorageID, repo.StorageNamespace, graveler.MetaRangeID("base")).DoAndReturn(func(context.Context, graveler.StorageID, graveler.StorageNamespace, graveler.MetaRangeID) (graveler.ValueIterator, error) {
				return catalog.NewFakeValueIterator(nil), nil
			}).AnyTimes()
			test.CommittedManager.EXPECT().Diff(gomock.Any(), repo.StorageID, repo.StorageNamespace, graveler.MetaRangeID("base"), graveler.MetaRangeID("compacted")).DoAndReturn(func(context.Context, graveler.StorageID, graveler.StorageNamespace, graveler.MetaRangeID, graveler.MetaRangeID) (graveler.DiffIterator, error) {
				return &filteredDiffIterator{diffs: diffRecords(map[string]string{"a-dir/b-compacted": "U", "b-hidden/file": "TS", "c-dir/compacted": "U", "z-last": "U"})}, nil
			}).AnyTimes()
			c := &catalog.Catalog{Store: test.Sut}
			filter := catalog.WithDiffPermissionFilter(t.Context(), diffAuthorizerFunc(func(ctx context.Context, req *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
				for _, node := range req.RequiredPermissions.Nodes {
					if node.Permission.ObjectMetadata["dcs:cls"] != "U" {
						return &auth.AuthorizationResponse{Allowed: false}, nil
					}
				}
				return &auth.AuthorizationResponse{Allowed: true}, nil
			}), "alice", "repo", "")
			var got []string
			after := ""
			for {
				diffs, more, err := c.DiffUncommitted(t.Context(), "repo", "main", "", "/", 1, after, filter)
				require.NoError(t, err)
				require.Len(t, diffs, 1)
				got = append(got, diffPaths(diffs)...)
				if !more {
					break
				}
				after = diffs[0].Path
				require.Less(t, len(got), 4, "pagination must advance")
			}
			require.Equal(t, []string{"a-dir/", "c-dir/", "z-last"}, got)
		})
	}
}

func TestCatalogDiffFilterComparisonEntriesOwnDecodedMetadata(t *testing.T) {
	t.Parallel()
	value := catalog.MustEntryToValue(&catalog.Entry{Metadata: map[string]string{"dcs:cls": "U"}})
	iter := &filteredDiffIterator{diffs: []graveler.Diff{{
		Key: graveler.Key("file"), Type: graveler.DiffTypeConflict,
		Value: value, LeftValue: value, BaseValue: value,
	}}}
	diffs, more, err := listFilteredDiff(t.Context(), diffCatalog(iter), "three-dot", catalog.DiffParams{Limit: 1}, catalog.WithDiffFilter(func(diff *catalog.EntryDiff) (bool, error) {
		require.NotSame(t, diff.Entry, diff.LeftEntry)
		require.NotSame(t, diff.Entry, diff.BaseEntry)
		diff.LeftEntry.Metadata["dcs:cls"] = "left changed"
		diff.BaseEntry.Metadata["dcs:cls"] = "base changed"
		value.Data = []byte{0xff}
		return true, nil
	}))
	require.NoError(t, err)
	require.False(t, more)
	require.Len(t, diffs, 1)
	require.Equal(t, "U", diffs[0].Metadata["dcs:cls"], "filter entries and mutable input must not change legacy response metadata")
}

type prefetchedFailureDiffIterator struct {
	filteredDiffIterator
	failure error
}

func (i *prefetchedFailureDiffIterator) Next() bool {
	more := i.filteredDiffIterator.Next()
	if more {
		i.err = i.failure
	}
	return more
}

func TestCatalogDiffFilterAbortsPrefetchedIteratorFailureBeforeDirectorySeek(t *testing.T) {
	t.Parallel()
	failure := errors.New("prefetched diff failed")
	iter := &prefetchedFailureDiffIterator{
		filteredDiffIterator: filteredDiffIterator{diffs: diffRecords(map[string]string{"dir/file": "U", "z": "U"})},
		failure:              failure,
	}
	c := &catalog.Catalog{Store: &catalog.FakeGraveler{DiffIteratorFactory: func() graveler.DiffIterator { return iter }}}
	checks := 0
	diffs, more, err := listFilteredDiff(t.Context(), c, "two-dot", catalog.DiffParams{Limit: 1, Delimiter: "/"}, catalog.WithDiffFilter(func(*catalog.EntryDiff) (bool, error) {
		checks++
		return true, nil
	}))
	require.ErrorIs(t, err, failure)
	require.Nil(t, diffs)
	require.False(t, more)
	require.Zero(t, checks, "a prefetched failure must not be discarded by a later delimiter seek")
	require.Equal(t, 1, iter.closes)
}
