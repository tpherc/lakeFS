package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
	"github.com/treeverse/lakefs/pkg/graveler"
)

const symlinkSpoolMode = 0o600

type symlinkRecord struct {
	Path    string
	Address string
}

func (c *Controller) exportSymlinks(ctx context.Context, repo *catalog.Repository, branch, prefix string) error {
	records, err := os.CreateTemp("", "lakefs-symlink-records-*")
	if err != nil {
		return fmt.Errorf("create export spool: %w", err)
	}
	defer func() {
		_ = records.Close()
		_ = os.Remove(records.Name())
	}()
	if err := c.captureSymlinkRecords(ctx, repo, branch, prefix, records); err != nil {
		return err
	}
	if _, err := records.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return publishSymlinkRecords(ctx, repo, branch, records, c.BlockAdapter)
}

// Capture and validate all selected bindings before publishing any manifest.
func (c *Controller) captureSymlinkRecords(ctx context.Context, repo *catalog.Repository, branch, prefix string, output io.Writer) error {
	encoder := json.NewEncoder(output)
	var after string
	for {
		entries, hasMore, err := c.Catalog.ListEntries(ctx, repo.Name, branch, prefix, after, "", DefaultMaxPerPage)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			pointer, err := entryObjectPointer(repo, entry)
			if err != nil {
				return err
			}
			if pointer.StorageID != repo.StorageID {
				return fmt.Errorf("URI-only symlink export cannot represent storage id %q at %q: %w", pointer.StorageID, entry.Path, block.ErrOperationNotSupported)
			}
			address, err := c.objectPhysicalAddress(pointer)
			if err != nil {
				return err
			}
			if err := encoder.Encode(symlinkRecord{Path: entry.Path, Address: address}); err != nil {
				return fmt.Errorf("capture export entry: %w", err)
			}
		}
		if !hasMore {
			return nil
		}
		if len(entries) == 0 || entries[len(entries)-1].Path <= after {
			return fmt.Errorf("export pagination did not advance: %w", graveler.ErrInvalid)
		}
		after = entries[len(entries)-1].Path
	}
}

type symlinkManifest struct {
	Path     string
	Filename string
}

// Publish only captured records; branch changes cannot replace the validated selection.
func publishSymlinkRecords(ctx context.Context, repo *catalog.Repository, branch string, records io.Reader, adapter block.Adapter) error {
	directory, err := os.MkdirTemp("", "lakefs-symlink-manifests-*")
	if err != nil {
		return fmt.Errorf("create manifest spool: %w", err)
	}
	defer func() { _ = os.RemoveAll(directory) }()
	index, err := os.Create(filepath.Join(directory, "index"))
	if err != nil {
		return err
	}
	defer func() { _ = index.Close() }()
	if err := spoolSymlinkManifests(ctx, records, directory, index); err != nil {
		return err
	}
	if _, err := index.Seek(0, io.SeekStart); err != nil {
		return err
	}
	decoder := json.NewDecoder(index)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var record symlinkManifest
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := writeSymlink(ctx, repo, branch, record.Path, filepath.Join(directory, record.Filename), adapter); err != nil {
			return err
		}
	}
}

// Parent directories are not contiguous in catalog order: a/file, a/sub/file, a/z.
// Separate disk-backed manifests preserve every address without retaining the whole export in memory.
func spoolSymlinkManifests(ctx context.Context, records io.Reader, directory string, index io.Writer) error {
	decoder := json.NewDecoder(records)
	encoder := json.NewEncoder(index)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var record symlinkRecord
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read captured export: %w", err)
		}
		var parent string
		if separator := strings.LastIndex(record.Path, "/"); separator >= 0 {
			parent = record.Path[:separator]
		}
		filename := fmt.Sprintf("%x", sha256.Sum256([]byte(parent)))
		manifestPath := filepath.Join(directory, filename)
		manifest, err := os.OpenFile(manifestPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, symlinkSpoolMode)
		content := record.Address
		if errors.Is(err, os.ErrExist) {
			manifest, err = os.OpenFile(manifestPath, os.O_WRONLY|os.O_APPEND, symlinkSpoolMode)
			content = "\n" + content
		} else if err == nil {
			err = encoder.Encode(symlinkManifest{Path: parent, Filename: filename})
			if err != nil {
				_ = manifest.Close()
				return err
			}
		}
		if err != nil {
			return err
		}
		_, writeErr := manifest.WriteString(content)
		closeErr := manifest.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return err
		}
	}
}

func writeSymlink(ctx context.Context, repo *catalog.Repository, branch, path, filename string, adapter block.Adapter) error {
	manifest, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = manifest.Close() }()
	info, err := manifest.Stat()
	if err != nil {
		return err
	}
	address := fmt.Sprintf("%s/%s/%s/%s/symlink.txt", lakeFSPrefix, repo.Name, branch, path)
	_, err = adapter.Put(ctx, block.ObjectPointer{
		StorageID:        repo.StorageID,
		StorageNamespace: repo.StorageNamespace,
		IdentifierType:   block.IdentifierTypeRelative,
		Identifier:       address,
	}, info.Size(), manifest, block.PutOpts{})
	return err
}
