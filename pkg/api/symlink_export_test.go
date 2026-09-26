package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
)

type symlinkTestAdapter struct {
	block.Adapter
	objects map[string]string
	onPut   func()
}

func (a *symlinkTestAdapter) Put(_ context.Context, pointer block.ObjectPointer, size int64, input io.Reader, _ block.PutOpts) (*block.PutResponse, error) {
	if a.onPut != nil {
		a.onPut()
	}
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != size {
		return nil, errors.New("incorrect manifest content length")
	}
	a.objects[pointer.Identifier] = string(content)
	return &block.PutResponse{}, nil
}

func TestSymlinkPublicationUsesCapturedRecords(t *testing.T) {
	liveRecords := []symlinkRecord{
		{Path: "a/file", Address: "s3://bucket/original-first"},
		{Path: "a/sub/file", Address: "s3://bucket/original-nested"},
		{Path: "a/z", Address: "s3://bucket/original-last"},
	}
	var captured bytes.Buffer
	for _, record := range liveRecords {
		require.NoError(t, json.NewEncoder(&captured).Encode(record))
	}
	adapter := &symlinkTestAdapter{objects: make(map[string]string), onPut: func() {
		// Simulate a branch update after validation, while publication is underway.
		for i := range liveRecords {
			liveRecords[i].Address = "s3://other/replaced"
		}
	}}
	require.NoError(t, publishSymlinkRecords(t.Context(), &catalog.Repository{Name: "repo", StorageID: "home", StorageNamespace: "s3://bucket/repo"}, "main", &captured, adapter))
	require.Equal(t, map[string]string{
		"symlinks/repo/main/a/symlink.txt":     "s3://bucket/original-first\ns3://bucket/original-last",
		"symlinks/repo/main/a/sub/symlink.txt": "s3://bucket/original-nested",
	}, adapter.objects)
	require.Equal(t, "s3://other/replaced", liveRecords[0].Address)
}

func TestSymlinkPublicationRejectsIncompleteCapture(t *testing.T) {
	adapter := &symlinkTestAdapter{objects: make(map[string]string)}
	input := bytes.NewBufferString("{\"Path\":\"a/file\",\"Address\":\"s3://bucket/object\"}\n{broken")
	err := publishSymlinkRecords(t.Context(), &catalog.Repository{Name: "repo"}, "main", input, adapter)
	require.Error(t, err)
	require.Empty(t, adapter.objects)
}

func TestSymlinkPublicationCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	adapter := &symlinkTestAdapter{objects: make(map[string]string)}
	err := publishSymlinkRecords(ctx, &catalog.Repository{Name: "repo"}, "main", bytes.NewReader(nil), adapter)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, adapter.objects)
}
