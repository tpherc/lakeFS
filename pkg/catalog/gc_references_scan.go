package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"time"

	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/retention"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/writer"
	"google.golang.org/protobuf/proto"
)

const (
	gcReferencesPartBytes        = 8 << 20
	gcReferencesMaxPartBytes     = 16 << 20
	gcReferencesPartRows         = 10000
	gcReferencesRowGroupBytes    = 1 << 20
	gcReferencesMaxManifestItems = 16384
	gcReferencesMaxManifestBytes = 16 << 20
)

var (
	errGCReferencesReaderNotConfigured = errors.New("GC reference reader is not configured")
	errGCReferencesLimitExceeded       = errors.New("GC reference artifact limit exceeded")
	errGCReferencesMissingPolicy       = errors.New("GC policy lookup returned no rules")
)

type gcReferenceRow struct {
	PhysicalAddress string `parquet:"name=physical_address, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
}

type gcReferencePartWriter struct {
	file    *os.File
	parquet *writer.ParquetWriter
	hash    hash.Hash
	rows    int64
	bytes   int64
}

func newGCReferencePartWriter() (*gcReferencePartWriter, error) {
	file, err := os.CreateTemp("", "lakefs-gc-reference-part-")
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	pw, err := writer.NewParquetWriterFromWriter(io.MultiWriter(file, hash), new(gcReferenceRow), gcParquetParallelNum)
	if err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	pw.CompressionType = parquet.CompressionCodec_GZIP
	pw.RowGroupSize = gcReferencesRowGroupBytes
	return &gcReferencePartWriter{file: file, parquet: pw, hash: hash}, nil
}

func (p *gcReferencePartWriter) close() {
	_ = p.file.Close()
	_ = os.Remove(p.file.Name())
}

func (p *gcReferencePartWriter) write(address string) error {
	if err := p.parquet.Write(gcReferenceRow{PhysicalAddress: address}); err != nil {
		return err
	}
	p.rows++
	p.bytes += int64(len(address))
	return nil
}

func (c *Catalog) prepareGCReferenceArtifacts(ctx context.Context, owner *graveler.RepositoryRecord, manifest *GCReferencesManifest, progress *gcReferencesProgress) (*GCReferencesResult, error) {
	return c.prepareGCReferenceArtifactsWithWriter(ctx, owner, manifest, progress, newGCReferencePartWriter)
}

func (c *Catalog) prepareGCReferenceArtifactsWithWriter(ctx context.Context, owner *graveler.RepositoryRecord, manifest *GCReferencesManifest, progress *gcReferencesProgress, createPart func() (*gcReferencePartWriter, error)) (*GCReferencesResult, error) {
	if c.gcReferencesRefs == nil {
		return nil, errGCReferencesReaderNotConfigured
	}
	base, err := c.gcReferencesLocation(owner, manifest.TaskID)
	if err != nil {
		return nil, err
	}
	var part *gcReferencePartWriter
	defer func() {
		if part != nil {
			part.close()
		}
	}()
	flush := func() error {
		if part == nil {
			return nil
		}
		if len(manifest.Parts) >= gcReferencesMaxManifestItems {
			return fmt.Errorf("manifest part count: %w", errGCReferencesLimitExceeded)
		}
		location := appendGCReferencePath(base, fmt.Sprintf("part-%06d.parquet", len(manifest.Parts)))
		info, err := c.uploadGCReferencePart(ctx, owner, part, location)
		if err != nil {
			return err
		}
		if err := part.file.Close(); err != nil {
			return fmt.Errorf("close reference part: %w", err)
		}
		manifest.Parts = append(manifest.Parts, info)
		manifest.TotalRows += part.rows
		_ = os.Remove(part.file.Name())
		part = nil
		return nil
	}
	emit := func(source *graveler.RepositoryRecord, value *graveler.Value) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		manifest.EntryCount++
		progress.entries.Add(1)
		entry, err := ValueToEntry(value)
		if err != nil {
			return err
		}
		obj, err := block.NewObjectPointer(entry.StorageId, source.StorageID.String(), source.StorageNamespace.String(), entry.Address, addressTypeToCatalog(entry.AddressType).ToIdentifierType())
		if err != nil {
			return err
		}
		fullAddress, err := obj.FullAddress()
		if err != nil {
			return err
		}
		address, owned, err := c.GCOwnedRelativeAddress(gcReferencesRepository(owner), obj.StorageID, fullAddress)
		if err != nil {
			return err
		}
		if !owned {
			return nil
		}
		if part == nil {
			part, err = createPart()
			if err != nil {
				return err
			}
		}
		if err := part.write(address); err != nil {
			return err
		}
		if part.rows >= gcReferencesPartRows || part.bytes >= gcReferencesPartBytes {
			return flush()
		}
		return nil
	}
	repositories, err := c.Store.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	defer repositories.Close()
	for repositories.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(manifest.Sources) >= gcReferencesMaxManifestItems {
			return nil, fmt.Errorf("manifest source count: %w", errGCReferencesLimitExceeded)
		}
		source := repositories.Value()
		if err := c.scanGCReferencesSource(ctx, source, manifest, emit); err != nil {
			return nil, fmt.Errorf("scan references in repository %s: %w", source.RepositoryID, err)
		}
		manifest.SourceCount++
	}
	if err := repositories.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.validateGCReferencesContext(ctx, owner, &gcReferencesState{Manifest: *manifest}); err != nil {
		return nil, err
	}
	return c.publishGCReferencesManifest(ctx, owner, base, manifest)
}

func (c *Catalog) publishGCReferencesManifest(ctx context.Context, owner *graveler.RepositoryRecord, base string, manifest *GCReferencesManifest) (*GCReferencesResult, error) {
	manifest.CompletedAt = time.Now().UTC()
	manifest.ExpiresAt = manifest.CompletedAt.Add(GCReferencesLifetime)
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if len(data) > gcReferencesMaxManifestBytes {
		return nil, fmt.Errorf("manifest bytes: %w", errGCReferencesLimitExceeded)
	}
	location := appendGCReferencePath(base, "manifest.json")
	if err := c.putGCReferenceArtifact(ctx, owner, location, int64(len(data)), bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return &GCReferencesResult{ManifestLocation: location, ManifestSHA256: gcReferencesDigest(data), ExpiresAt: manifest.ExpiresAt}, nil
}

func (c *Catalog) gcReferencesLocation(owner *graveler.RepositoryRecord, taskID string) (string, error) {
	// Use the existing metadata location provider, keeping all artifacts on the owner.
	base, err := c.Store.GCGetUncommittedLocation(owner, taskID)
	if err != nil {
		return "", err
	}
	return appendGCReferencePath(base, "references"), nil
}

// Components are generated by this package. URL path cleaning would change native
// object keys containing repeated slashes, percent escapes or dot components.
func appendGCReferencePath(base, component string) string {
	return strings.TrimSuffix(base, "/") + "/" + component
}

func (c *Catalog) putGCReferenceArtifact(ctx context.Context, owner *graveler.RepositoryRecord, location string, size int64, content io.Reader) error {
	_, err := c.BlockAdapter.Put(ctx, block.ObjectPointer{StorageID: owner.StorageID.String(), Identifier: location, IdentifierType: block.IdentifierTypeFull}, size, content, block.PutOpts{})
	return err
}

func (c *Catalog) uploadGCReferencePart(ctx context.Context, owner *graveler.RepositoryRecord, part *gcReferencePartWriter, location string) (GCReferencesPart, error) {
	if err := part.parquet.WriteStop(); err != nil {
		return GCReferencesPart{}, err
	}
	info, err := part.file.Stat()
	if err != nil {
		return GCReferencesPart{}, err
	}
	if info.Size() > gcReferencesMaxPartBytes {
		return GCReferencesPart{}, fmt.Errorf("part bytes: %w", errGCReferencesLimitExceeded)
	}
	if _, err := part.file.Seek(0, io.SeekStart); err != nil {
		return GCReferencesPart{}, err
	}
	if err := c.putGCReferenceArtifact(ctx, owner, location, info.Size(), part.file); err != nil {
		return GCReferencesPart{}, err
	}
	return GCReferencesPart{Location: location, SHA256: hex.EncodeToString(part.hash.Sum(nil)), RowCount: part.rows, SizeBytes: info.Size()}, nil
}

func gcReferencesDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (c *Catalog) scanGCReferencesSource(ctx context.Context, source *graveler.RepositoryRecord, manifest *GCReferencesManifest, emit func(*graveler.RepositoryRecord, *graveler.Value) error) error {
	if err := c.validateGCReferencesSource(ctx, source); err != nil {
		return err
	}
	// Staging must finish before collecting committed roots: a concurrent commit can
	// move an entry from staging into history between these phases.
	if err := c.scanGCReferencesStaging(ctx, source, emit); err != nil {
		return err
	}
	rules, err := c.Store.GetGarbageCollectionRules(ctx, source)
	if err != nil && !errors.Is(err, graveler.ErrNotFound) {
		return err
	}
	provenance := GCReferencesSource{RepositoryID: source.RepositoryID.String(), RepositoryInstanceUID: source.InstanceUID, EvaluatedAt: manifest.StartedAt, NoPolicy: errors.Is(err, graveler.ErrNotFound)}
	if provenance.NoPolicy {
		rules = nil
	} else {
		if rules == nil {
			return errGCReferencesMissingPolicy
		}
		data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(rules)
		if err != nil {
			return err
		}
		provenance.PolicySHA256 = gcReferencesDigest(data)
	}
	manifest.Sources = append(manifest.Sources, provenance)
	err = retention.ForEachRetainedCommit(ctx, c.gcReferencesRefs, source, rules, provenance.EvaluatedAt, func(commitID graveler.CommitID, _ graveler.MetaRangeID) error {
		manifest.CommitCount++
		values, err := c.Store.List(ctx, source, graveler.Ref(commitID), 0)
		if err != nil {
			return err
		}
		defer values.Close()
		for values.Next() {
			if err := emit(source, values.Value().Value); err != nil {
				return err
			}
		}
		return values.Err()
	})
	if err != nil {
		return err
	}
	return c.validateGCReferencesSource(ctx, source)
}

func (c *Catalog) validateGCReferencesSource(ctx context.Context, source *graveler.RepositoryRecord) error {
	current, err := c.readGCReferencesRepository(ctx, source.RepositoryID)
	if err != nil {
		return err
	}
	if current.InstanceUID != source.InstanceUID || current.StorageID != source.StorageID || current.StorageNamespace != source.StorageNamespace {
		return fmt.Errorf("source repository changed: %w", ErrGCReferencesInvalid)
	}
	return nil
}

func (c *Catalog) scanGCReferencesStaging(ctx context.Context, source *graveler.RepositoryRecord, emit func(*graveler.RepositoryRecord, *graveler.Value) error) error {
	branches, err := c.Store.ListBranches(ctx, source, graveler.WithShowHidden(true))
	if err != nil {
		return err
	}
	defer branches.Close()
	for branches.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.scanGCReferencesBranch(ctx, source, branches.Value().BranchID, emit); err != nil {
			return err
		}
	}
	return branches.Err()
}

func (c *Catalog) scanGCReferencesBranch(ctx context.Context, source *graveler.RepositoryRecord, branch graveler.BranchID, emit func(*graveler.RepositoryRecord, *graveler.Value) error) error {
	changes, err := c.Store.DiffUncommitted(ctx, source, branch)
	if err != nil {
		return err
	}
	defer changes.Close()
	for changes.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		change := changes.Value()
		if change.Type == graveler.DiffTypeRemoved {
			continue
		}
		if err := emit(source, change.Value); err != nil {
			return err
		}
	}
	return changes.Err()
}
