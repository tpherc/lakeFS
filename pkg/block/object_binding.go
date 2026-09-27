package block

import "fmt"

// EffectiveStorageID selects an explicit binding or the resolved repository home.
func EffectiveStorageID(storageID, repositoryStorageID string) string {
	if storageID != "" {
		return storageID
	}
	return repositoryStorageID
}

// NewObjectPointer binds an entry to storage without consulting an adapter.
// A foreign binding must carry its own full address instead of inheriting the home namespace.
func NewObjectPointer(storageID, repositoryStorageID, namespace, address string, addressType IdentifierType) (ObjectPointer, error) {
	effectiveID := EffectiveStorageID(storageID, repositoryStorageID)
	if effectiveID != repositoryStorageID && addressType != IdentifierTypeFull {
		return ObjectPointer{}, fmt.Errorf("storage id %q requires a full object address: %w", effectiveID, ErrInvalidAddress)
	}
	if addressType == IdentifierTypeFull {
		// Some adapters infer relative addresses from syntax even for FULL pointers.
		// FULL locators must never be expanded in the repository home namespace.
		namespace = ""
	}
	return ObjectPointer{
		StorageID:        effectiveID,
		StorageNamespace: namespace,
		Identifier:       address,
		IdentifierType:   addressType,
	}, nil
}

// FullAddress expands native pointers without adapter-specific configuration.
// Use Adapter.ResolveNamespace when formatting relative addresses for external
// consumers, because local storage also needs its configured root directory.
func (obj ObjectPointer) FullAddress() (string, error) {
	if obj.IdentifierType == IdentifierTypeFull {
		return obj.Identifier, nil
	}
	qk, err := DefaultResolveNamespace(obj.StorageNamespace, obj.Identifier, obj.IdentifierType)
	if err != nil {
		return "", err
	}
	return qk.Format(), nil
}
