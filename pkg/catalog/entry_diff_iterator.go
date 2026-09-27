package catalog

import "github.com/treeverse/lakefs/pkg/graveler"

type entryDiffIterator struct {
	it     graveler.DiffIterator
	value  *EntryDiff
	err    error
	decode func(*graveler.Diff) (*EntryDiff, error)
}

func NewEntryDiffIterator(it graveler.DiffIterator) EntryDiffIterator {
	return &entryDiffIterator{it: it, decode: decodeEntryDiff}
}

func newDiffListingIterator(it graveler.DiffIterator, options DiffOptions) EntryDiffIterator {
	if options.FilterFunc == nil {
		return NewEntryDiffIterator(it)
	}
	return &entryDiffIterator{it: it, decode: decodeComparisonEntryDiff}
}

func decodeEntryDiff(diff *graveler.Diff) (*EntryDiff, error) {
	entry, err := ValueToEntry(diff.Value)
	if err != nil {
		return nil, err
	}
	return &EntryDiff{Type: diff.Type, Path: Path(diff.Key), Entry: entry}, nil
}

func decodeComparisonEntryDiff(diff *graveler.Diff) (*EntryDiff, error) {
	entry, err := decodeEntryDiff(diff)
	if err != nil {
		return nil, err
	}
	entry.LeftEntry, err = ValueToEntry(diff.LeftValue)
	if err != nil {
		return nil, err
	}
	entry.BaseEntry, err = ValueToEntry(diff.BaseValue)
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (e *entryDiffIterator) Next() bool {
	if e.err != nil {
		return false
	}
	more := e.it.Next()
	if e.err = e.it.Err(); e.err != nil || !more {
		e.value = nil
		return false
	}
	e.value, e.err = e.decode(e.it.Value())
	return e.err == nil
}

func (e *entryDiffIterator) SeekGE(id Path) {
	e.value = nil
	key := graveler.Key(id)
	e.it.SeekGE(key)
}

func (e *entryDiffIterator) Value() *EntryDiff {
	return e.value
}

func (e *entryDiffIterator) Err() error {
	return e.err
}

func (e *entryDiffIterator) Close() {
	e.it.Close()
}
