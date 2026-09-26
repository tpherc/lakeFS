package catalog

import "context"

type entryFilterIterator struct {
	ctx    context.Context
	it     EntryIterator
	filter func(*DBEntry) (bool, error)
	value  *EntryRecord
	err    error
}

func (e *entryFilterIterator) Next() bool {
	e.value = nil
	if e.err != nil {
		return false
	}
	for {
		if e.err = e.ctx.Err(); e.err != nil {
			return false
		}
		if !e.it.Next() {
			e.err = e.it.Err()
			return false
		}
		value := e.it.Value()
		entry := newCatalogEntryFromEntry(false, value.Path.String(), value.Entry)
		allowed, err := e.filter(&entry)
		if err != nil {
			e.err = err
			return false
		}
		if e.err = e.ctx.Err(); e.err != nil {
			return false
		}
		if allowed {
			e.value = value
			return true
		}
	}
}

func (e *entryFilterIterator) SeekGE(path Path) {
	e.value = nil
	e.it.SeekGE(path)
}

func (e *entryFilterIterator) Value() *EntryRecord {
	return e.value
}

func (e *entryFilterIterator) Err() error {
	return e.err
}

func (e *entryFilterIterator) Close() {
	e.it.Close()
}
