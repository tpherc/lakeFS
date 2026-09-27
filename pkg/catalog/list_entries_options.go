package catalog

// ListEntriesOptions controls which stored entries may appear in a listing.
type ListEntriesOptions struct {
	FilterFunc func(*DBEntry) (bool, error)
}

type ListEntriesOptionsFunc func(*ListEntriesOptions)

// WithEntryFilter filters stored objects before delimiter grouping and pagination.
// A common prefix is returned only if it contains an admitted object. The filter
// must not mutate the entry. Any error aborts the listing without partial results.
func WithEntryFilter(filter func(*DBEntry) (bool, error)) ListEntriesOptionsFunc {
	return func(opts *ListEntriesOptions) {
		opts.FilterFunc = filter
	}
}
