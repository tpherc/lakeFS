package api

import (
	"errors"
	"strings"

	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/catalog"
)

func optionalStorageID(storageID string) *string {
	if storageID == "" {
		return nil
	}
	return &storageID
}

func entryObjectPointer(repo *catalog.Repository, entry *catalog.DBEntry) (block.ObjectPointer, error) {
	return block.NewObjectPointer(entry.StorageID, repo.StorageID, repo.StorageNamespace, entry.PhysicalAddress, entry.AddressType.ToIdentifierType())
}

func (c *Controller) resolveObjectStorageID(repositoryStorageID, requestedStorageID string) (string, error) {
	storageID := block.EffectiveStorageID(requestedStorageID, repositoryStorageID)
	if err := c.Config.StorageConfig().ValidateObjectStorageID(storageID); err != nil {
		return "", err
	}
	return storageID, nil
}

func (c *Controller) normalizeObjectAddress(repo *catalog.Repository, storageID, address string) (string, catalog.AddressType, string) {
	if storageID != repo.StorageID {
		return address, catalog.AddressTypeFull, storageID
	}
	physicalAddress, addressType := c.normalizePhysicalAddress(repo.StorageNamespace, address)
	if addressType == catalog.AddressTypeRelative {
		return physicalAddress, addressType, ""
	}
	return physicalAddress, addressType, storageID
}

func (c *Controller) verifyManagedLink(repo *catalog.Repository, storageID, address, repository, branch, path string) error {
	if storageID == repo.StorageID {
		relative, addressType := c.normalizePhysicalAddress(repo.StorageNamespace, address)
		if addressType == catalog.AddressTypeRelative {
			return c.Catalog.VerifyLinkAddress(repository, branch, path, relative)
		}
	}

	relative, owned, err := c.Catalog.OwnedRelativeAddress(repo, storageID, address)
	if errors.Is(err, block.ErrInvalidAddress) {
		// Link accepts opaque external addresses; Stage owns native syntax validation.
		return nil
	}
	if err != nil {
		return err
	}
	managedPrefix := strings.TrimSuffix(c.PathProvider.CommonPrefix(), catalog.DefaultPathDelimiter) + catalog.DefaultPathDelimiter
	if owned && strings.HasPrefix(relative, managedPrefix) {
		return c.Catalog.VerifyLinkAddress(repository, branch, path, relative)
	}
	return nil
}

// FULL metadata remains readable without its adapter. Home-relative addresses
// still use the adapter's namespace rules, including the configured local root.
func (c *Controller) objectPhysicalAddress(pointer block.ObjectPointer) (string, error) {
	if pointer.IdentifierType == block.IdentifierTypeFull {
		return pointer.Identifier, nil
	}
	key, err := c.BlockAdapter.ResolveNamespace(pointer.StorageID, pointer.StorageNamespace, pointer.Identifier, pointer.IdentifierType)
	if err != nil {
		return "", err
	}
	return key.Format(), nil
}
