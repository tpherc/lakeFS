package committed_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/committed"
	"github.com/treeverse/lakefs/pkg/graveler/committed/mock"
	"github.com/treeverse/lakefs/pkg/graveler/testutil"
)

func TestIteratorPropagatesMetaRangeFailure(t *testing.T) {
	t.Parallel()
	failure := errors.New("metadata range unavailable")
	ranges := mock.NewMockValueIterator(gomock.NewController(t))
	ranges.EXPECT().Next().Return(false)
	ranges.EXPECT().Err().Return(failure).AnyTimes()
	ranges.EXPECT().Close()
	it := committed.NewIterator(t.Context(), nil, "ns", ranges)
	t.Cleanup(it.Close)
	require.False(t, it.Next())
	require.ErrorIs(t, it.Err(), failure)
}

func TestIteratorPropagatesRangeFailure(t *testing.T) {
	t.Parallel()
	for _, afterValue := range []bool{false, true} {
		name := "first value"
		if afterValue {
			name = "after a value"
		}
		t.Run(name, func(t *testing.T) {
			failure := errors.New("object metadata range unavailable")
			ctrl := gomock.NewController(t)
			data := mock.NewMockValueIterator(ctrl)
			if afterValue {
				data.EXPECT().Next().Return(true)
				data.EXPECT().Value().Return(&committed.Record{
					Key:   committed.Key("a"),
					Value: committed.MustMarshalValue(&graveler.Value{Identity: []byte("a"), Data: []byte("entry")}),
				})
			}
			data.EXPECT().Next().Return(false)
			data.EXPECT().Err().Return(failure).AnyTimes()
			data.EXPECT().Close()
			manager := mock.NewMockRangeManager(ctrl)
			manager.EXPECT().NewRangeIterator(gomock.Any(), committed.Namespace("ns"), committed.ID("z")).Return(data, nil)
			ranges := testutil.NewCommittedValueIteratorFake(makeRangeRecords([]rangeKeys{{Name: "z", Keys: makeKeys("a", "z")}}))
			it := committed.NewIterator(t.Context(), manager, "ns", ranges)
			t.Cleanup(it.Close)
			require.True(t, it.Next(), "range header")
			if afterValue {
				require.True(t, it.Next())
			}
			require.False(t, it.Next())
			require.ErrorIs(t, it.Err(), failure, "range errors must not become successful end of iteration")
			require.False(t, it.Next())
			require.ErrorIs(t, it.Err(), failure, "failure remains visible after another Next")
		})
	}
}
