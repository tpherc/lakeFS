package graveler

import (
	"bytes"
	"context"
	"fmt"
)

type uncommittedDiffIterator struct {
	committedList   ValueIterator
	uncommittedList ValueIterator
	value           *Diff
	err             error
	ctx             context.Context
}

// NewUncommittedDiffIterator lists uncommitted changes as a diff. If `metaRangeID` is empty then there is no commit and it returns all objects as added
func NewUncommittedDiffIterator(ctx context.Context, committedList ValueIterator, uncommittedList ValueIterator) DiffIterator {
	return &uncommittedDiffIterator{
		ctx:             ctx,
		committedList:   committedList,
		uncommittedList: uncommittedList,
	}
}

// committedValue returns the exact historical entry used to classify the change.
func (d *uncommittedDiffIterator) committedValue(key Key) (*Value, error) {
	if d.committedList == nil {
		return nil, nil
	}
	d.committedList.SeekGE(key)
	if d.committedList.Next() {
		record := d.committedList.Value()
		if record == nil {
			return nil, fmt.Errorf("missing committed record: %w", ErrInvalidValue)
		}
		if bytes.Equal(record.Key, key) {
			if record.Value == nil {
				return nil, fmt.Errorf("missing committed value: %w", ErrInvalidValue)
			}
			return record.Value, nil
		}
	}
	return nil, d.committedList.Err()
}

func uncommittedDiffType(value, committed *Value) (DiffType, bool) {
	switch {
	case value == nil:
		return DiffTypeRemoved, committed == nil
	case committed == nil:
		return DiffTypeAdded, false
	default:
		return DiffTypeChanged, bytes.Equal(committed.Identity, value.Identity)
	}
}

func (d *uncommittedDiffIterator) Next() bool {
	for {
		if d.err != nil {
			return false
		}
		if err := d.ctx.Err(); err != nil {
			d.value = nil
			d.err = err
			return false
		}
		if !d.uncommittedList.Next() {
			d.err = d.uncommittedList.Err()
			d.value = nil
			return false
		}
		val := d.uncommittedList.Value()
		committed, err := d.committedValue(val.Key)
		if err != nil {
			d.value = nil
			d.err = err
			return false
		}
		diffType, skip := uncommittedDiffType(val.Value, committed)
		if skip {
			continue
		}
		d.value = (&Diff{
			Type: diffType, Key: val.Key, Value: val.Value,
			LeftValue: committed,
		}).Copy()
		return true
	}
}

func (d *uncommittedDiffIterator) SeekGE(id Key) {
	d.value = nil
	d.err = nil
	d.uncommittedList.SeekGE(id)
}

func (d *uncommittedDiffIterator) Value() *Diff {
	return d.value
}

func (d *uncommittedDiffIterator) Err() error {
	return d.err
}

func (d *uncommittedDiffIterator) Close() {
	d.uncommittedList.Close()
	if d.committedList != nil {
		d.committedList.Close()
	}
}
