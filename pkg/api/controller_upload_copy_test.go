package api

import (
	"context"
	"io"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
)

const uploadCopyTestID = "upload-id"

type uploadCopyCall struct {
	context     context.Context
	source      block.ObjectPointer
	destination block.ObjectPointer
	uploadID    string
	partNumber  int
	byteRange   *[2]int64
}

type uploadCopyTestAdapter struct {
	block.Adapter
	calls    []uploadCopyCall
	response *block.UploadPartResponse
	err      error
}

func (a *uploadCopyTestAdapter) UploadCopyPart(ctx context.Context, source, destination block.ObjectPointer, uploadID string, partNumber int) (*block.UploadPartResponse, error) {
	a.calls = append(a.calls, uploadCopyCall{context: ctx, source: source, destination: destination, uploadID: uploadID, partNumber: partNumber})
	return a.response, a.err
}

func (a *uploadCopyTestAdapter) UploadCopyPartRange(ctx context.Context, source, destination block.ObjectPointer, uploadID string, partNumber int, startPosition, endPosition int64) (*block.UploadPartResponse, error) {
	a.calls = append(a.calls, uploadCopyCall{context: ctx, source: source, destination: destination, uploadID: uploadID, partNumber: partNumber, byteRange: &[2]int64{startPosition, endPosition}})
	return a.response, a.err
}

func TestUploadCopyPartPreservesStorageRequest(t *testing.T) {
	source := block.ObjectPointer{StorageID: "source-store", StorageNamespace: "s3://source/repo", Identifier: "data/source", IdentifierType: block.IdentifierTypeRelative}
	destination := block.ObjectPointer{StorageID: "destination-store", StorageNamespace: "s3://destination/repo", Identifier: "data/destination", IdentifierType: block.IdentifierTypeRelative}
	tests := []struct {
		name      string
		copyRange *string
		wantRange *[2]int64
	}{
		{name: "whole object"},
		{name: "inclusive byte range", copyRange: swag.String("bytes=10-29"), wantRange: &[2]int64{10, 29}},
		{name: "negative positions retained for blockstore", copyRange: swag.String("bytes=-10--1"), wantRange: &[2]int64{-10, -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			adapter := &uploadCopyTestAdapter{response: &block.UploadPartResponse{ETag: `"copied-part-etag"`}}
			controller := Controller{BlockAdapter: adapter}

			etag, err := controller.uploadCopyPart(ctx, source, destination, uploadCopyTestID, 7, test.copyRange)

			require.NoError(t, err)
			require.Equal(t, `"copied-part-etag"`, etag)
			require.Equal(t, []uploadCopyCall{{context: ctx, source: source, destination: destination, uploadID: uploadCopyTestID, partNumber: 7, byteRange: test.wantRange}}, adapter.calls)
		})
	}
}

func TestUploadCopyPartPropagatesBackendErrors(t *testing.T) {
	tests := []struct {
		name      string
		copyRange *string
	}{
		{name: "whole object"},
		{name: "byte range", copyRange: swag.String("bytes=0-9")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := &uploadCopyTestAdapter{err: io.ErrUnexpectedEOF}
			controller := Controller{BlockAdapter: adapter}

			etag, err := controller.uploadCopyPart(t.Context(), block.ObjectPointer{}, block.ObjectPointer{}, uploadCopyTestID, 1, test.copyRange)

			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			require.Empty(t, etag)
			require.Len(t, adapter.calls, 1)
		})
	}
}

func TestUploadCopyPartRejectsMalformedRangeBeforeStorage(t *testing.T) {
	for _, copyRange := range []string{"", "bytes=0-", "bytes=first-last", "items=0-9"} {
		t.Run(copyRange, func(t *testing.T) {
			adapter := &uploadCopyTestAdapter{}
			controller := Controller{BlockAdapter: adapter}

			etag, err := controller.uploadCopyPart(t.Context(), block.ObjectPointer{}, block.ObjectPointer{}, uploadCopyTestID, 1, &copyRange)

			require.ErrorContains(t, err, "parse range")
			require.Empty(t, etag)
			require.Empty(t, adapter.calls)
		})
	}
}
