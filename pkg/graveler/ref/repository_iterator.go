package ref

import (
	"context"
	"errors"
	"fmt"

	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/kv"
)

type RepositoryIterator struct {
	ctx           context.Context
	storageConfig config.StorageConfig
	it            kv.MessageIterator
	err           error
	value         *graveler.RepositoryRecord
	store         kv.Store
	closed        bool
}

func NewRepositoryIterator(ctx context.Context, store kv.Store, storageConfig config.StorageConfig) (*RepositoryIterator, error) {
	it, err := kv.NewPrimaryIterator(ctx, store, (&graveler.RepositoryData{}).ProtoReflect().Type(), graveler.RepositoriesPartition(), []byte(graveler.RepoPath("")), kv.IteratorOptionsAfter([]byte{}))
	if err != nil {
		return nil, err
	}
	return &RepositoryIterator{
		ctx:           ctx,
		storageConfig: storageConfig,
		it:            it,
		store:         store,
		closed:        false,
	}, nil
}

func (ri *RepositoryIterator) Next() bool {
	if ri.Err() != nil || ri.closed {
		return false
	}

	if !ri.it.Next() {
		ri.value = nil
		return false
	}
	e := ri.it.Entry()
	if e == nil {
		ri.err = graveler.ErrInvalid
		return false
	}

	repo, ok := e.Value.(*graveler.RepositoryData)
	if repo == nil || !ok {
		ri.err = graveler.ErrReadingFromStore
		return false
	}

	ri.value = graveler.RepoFromProto(repo)
	storageID, err := ri.storageConfig.ResolveStoredRepositoryStorageID(ri.value.StorageID.String())
	if err != nil {
		ri.err = fmt.Errorf("repository %q storage id %q: %w", ri.value.RepositoryID, ri.value.StorageID, err)
		ri.value = nil
		return false
	}
	ri.value.StorageID = graveler.StorageID(storageID)
	return true
}

func (ri *RepositoryIterator) SeekGE(id graveler.RepositoryID) {
	if errors.Is(ri.Err(), kv.ErrClosedEntries) {
		return
	}
	ri.Close()
	ri.it, ri.err = kv.NewPrimaryIterator(ri.ctx, ri.store, (&graveler.RepositoryData{}).ProtoReflect().Type(), graveler.RepositoriesPartition(), []byte(graveler.RepoPath("")), kv.IteratorOptionsFrom([]byte(graveler.RepoPath(id))))
	ri.closed = ri.err != nil
	ri.value = nil
}

func (ri *RepositoryIterator) Value() *graveler.RepositoryRecord {
	if ri.Err() != nil {
		return nil
	}
	return ri.value
}

func (ri *RepositoryIterator) Err() error {
	if ri.err != nil {
		return ri.err
	}
	if !ri.closed {
		return ri.it.Err()
	}
	return nil
}

func (ri *RepositoryIterator) Close() {
	if ri.closed {
		return
	}
	ri.it.Close()
	ri.closed = true
}

func ValidateRepositoryStorageIDs(ctx context.Context, store kv.Store, storageConfig config.StorageConfig) error {
	it, err := kv.NewPrimaryIterator(ctx, store, (&graveler.RepositoryData{}).ProtoReflect().Type(), graveler.RepositoriesPartition(), []byte(graveler.RepoPath("")), kv.IteratorOptionsAfter([]byte{}))
	if err != nil {
		return err
	}
	defer it.Close()

	for it.Next() {
		entry := it.Entry()
		if entry == nil {
			return graveler.ErrInvalid
		}
		data, ok := entry.Value.(*graveler.RepositoryData)
		if data == nil || !ok {
			return graveler.ErrReadingFromStore
		}
		repo := graveler.RepoFromProto(data)
		if _, err := storageConfig.ResolveStoredRepositoryStorageID(repo.StorageID.String()); err != nil {
			return fmt.Errorf("repository %q storage id %q: %w", repo.RepositoryID, repo.StorageID, err)
		}
	}
	return it.Err()
}
