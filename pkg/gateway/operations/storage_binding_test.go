package operations

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type bindingStore struct {
	catalog.Store
	value *graveler.Value
}

func (s *bindingStore) GetRepository(context.Context, graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	return &graveler.RepositoryRecord{RepositoryID: "repo", Repository: &graveler.Repository{StorageID: "home", StorageNamespace: "s3://bucket/home"}}, nil
}

func (s *bindingStore) Get(context.Context, *graveler.RepositoryRecord, graveler.Ref, graveler.Key, ...graveler.GetOptionsFunc) (*graveler.Value, error) {
	return s.value, nil
}

type bindingAdapter struct {
	block.Adapter
	pointers []block.ObjectPointer
	ranges   [][2]int64
}

func (a *bindingAdapter) Get(_ context.Context, pointer block.ObjectPointer) (io.ReadCloser, error) {
	a.pointers = append(a.pointers, pointer)
	return io.NopCloser(strings.NewReader("content")), nil
}

func (a *bindingAdapter) GetRange(_ context.Context, pointer block.ObjectPointer, start, end int64) (io.ReadCloser, error) {
	a.pointers = append(a.pointers, pointer)
	a.ranges = append(a.ranges, [2]int64{start, end})
	return io.NopCloser(strings.NewReader("content"[start : end+1])), nil
}

func (a *bindingAdapter) GetPreSignedURL(_ context.Context, pointer block.ObjectPointer, _ block.PreSignMode, _ string) (string, time.Time, error) {
	a.pointers = append(a.pointers, pointer)
	return "https://source.example/object", time.Time{}, nil
}

func TestGetObjectUsesSavedSourceBinding(t *testing.T) {
	for _, test := range []struct {
		name           string
		source         string
		addressType    catalog.Entry_AddressType
		rangeHeader    string
		redirect       bool
		status         int
		expectedSource string
	}{
		{name: "read", source: "foreign", addressType: catalog.Entry_FULL, status: http.StatusOK, expectedSource: "foreign"},
		{name: "range", source: "foreign", addressType: catalog.Entry_FULL, rangeHeader: "bytes=0-2", status: http.StatusPartialContent, expectedSource: "foreign"},
		{name: "multiple ranges fall back", source: "foreign", addressType: catalog.Entry_FULL, rangeHeader: "bytes=0-1,3-4", status: http.StatusOK, expectedSource: "foreign"},
		{name: "malformed range falls back", source: "foreign", addressType: catalog.Entry_FULL, rangeHeader: "bytes=invalid", status: http.StatusOK, expectedSource: "foreign"},
		{name: "unsupported unit falls back", source: "foreign", addressType: catalog.Entry_FULL, rangeHeader: "items=0-2", status: http.StatusOK, expectedSource: "foreign"},
		{name: "unsatisfiable range", source: "foreign", addressType: catalog.Entry_FULL, rangeHeader: "bytes=9-10", status: http.StatusRequestedRangeNotSatisfiable},
		{name: "presign", source: "foreign", addressType: catalog.Entry_FULL, redirect: true, status: http.StatusTemporaryRedirect, expectedSource: "foreign"},
		{name: "legacy", addressType: catalog.Entry_FULL, status: http.StatusOK, expectedSource: "home"},
		{name: "invalid foreign relative", source: "foreign", addressType: catalog.Entry_RELATIVE, status: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := catalog.EntryToValue(&catalog.Entry{Address: "gs://bucket/object", StorageId: test.source, AddressType: test.addressType, Size: 7, ETag: "etag", LastModified: timestamppb.Now()})
			require.NoError(t, err)
			adapter := &bindingAdapter{}
			operation := &PathOperation{RefOperation: &RefOperation{RepoOperation: &RepoOperation{AuthorizedOperation: &AuthorizedOperation{Operation: &Operation{
				Catalog:    &catalog.Catalog{Store: &bindingStore{value: value}},
				BlockStore: adapter,
				Incr:       func(string, string, string, string) {},
			}}, Repository: &catalog.Repository{Name: "repo", StorageID: "home", StorageNamespace: "s3://bucket/home"}}, Reference: "main"}, Path: "object"}
			request := httptest.NewRequest(http.MethodGet, "/repo/main/object", nil)
			if test.rangeHeader != "" {
				request.Header.Set("Range", test.rangeHeader)
			}
			if test.redirect {
				request.Header.Set("User-Agent", s3RedirectionSupportUserAgentTag)
			}
			response := httptest.NewRecorder()
			(&GetObject{}).Handle(response, request, operation)
			require.Equal(t, test.status, response.Code, response.Body.String())
			if test.expectedSource == "" {
				require.Empty(t, adapter.pointers)
				return
			}
			require.Len(t, adapter.pointers, 1)
			require.Equal(t, test.expectedSource, adapter.pointers[0].StorageID)
			require.Equal(t, block.IdentifierTypeFull, adapter.pointers[0].IdentifierType)
			require.Equal(t, "gs://bucket/object", adapter.pointers[0].Identifier)
			switch test.status {
			case http.StatusOK:
				require.Equal(t, "content", response.Body.String())
				require.Equal(t, "7", response.Header().Get("Content-Length"))
				require.Empty(t, response.Header().Get("Content-Range"))
				require.Empty(t, adapter.ranges)
			case http.StatusPartialContent:
				require.Equal(t, "con", response.Body.String())
				require.Equal(t, "3", response.Header().Get("Content-Length"))
				require.Equal(t, "bytes 0-2/7", response.Header().Get("Content-Range"))
				require.Equal(t, [][2]int64{{0, 2}}, adapter.ranges)
			}
		})
	}
}
