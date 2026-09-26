package block_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
)

func TestObjectBinding(t *testing.T) {
	for _, tc := range []struct {
		name, id, home, address, effectiveID, fullAddress string
		addressType                                       block.IdentifierType
		invalid                                           bool
	}{
		{name: "inherited relative", home: "home", address: "data/a", addressType: block.IdentifierTypeRelative, effectiveID: "home", fullAddress: "s3://bucket/repo/data/a"},
		{name: "explicit home relative", id: "home", home: "home", address: "data/a", addressType: block.IdentifierTypeRelative, effectiveID: "home", fullAddress: "s3://bucket/repo/data/a"},
		{name: "foreign full preserves native key", id: "source", home: "home", address: "gs://bucket/a//b%2Fc", addressType: block.IdentifierTypeFull, effectiveID: "source", fullAddress: "gs://bucket/a//b%2Fc"},
		{name: "home full has no namespace fallback", id: "home", home: "home", address: "data/a", addressType: block.IdentifierTypeFull, effectiveID: "home", fullAddress: "data/a"},
		{name: "foreign relative rejected", id: "source", home: "home", address: "data/a", addressType: block.IdentifierTypeRelative, invalid: true},
		{name: "foreign unspecified type rejected", id: "source", home: "home", address: "data/a", addressType: block.IdentifierTypeUnknownDeprecated, invalid: true},
		{name: "legacy single store", address: "data/a", addressType: block.IdentifierTypeRelative, fullAddress: "s3://bucket/repo/data/a"},
		{name: "legacy inferred full", address: "gs://bucket/a", addressType: block.IdentifierTypeUnknownDeprecated, fullAddress: "gs://bucket/a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj, err := block.NewObjectPointer(tc.id, tc.home, "s3://bucket/repo", tc.address, tc.addressType)
			if tc.invalid {
				require.ErrorIs(t, err, block.ErrInvalidAddress)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.effectiveID, obj.StorageID)
			if tc.addressType == block.IdentifierTypeFull {
				require.Empty(t, obj.StorageNamespace, "FULL pointers must not inherit home context")
			} else {
				require.Equal(t, "s3://bucket/repo", obj.StorageNamespace)
			}
			address, err := obj.FullAddress()
			require.NoError(t, err)
			require.Equal(t, tc.fullAddress, address)
		})
	}
}
