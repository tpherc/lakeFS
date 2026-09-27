package catalog

// DiffOptions controls visibility of raw changes before grouping and pagination.
type DiffOptions struct {
	FilterFunc func(*EntryDiff) (bool, error)
}

type DiffOptionsFunc func(*DiffOptions)

// WithDiffFilter admits changes using the compared entries. The predicate must
// not mutate those entries. Any error aborts the diff without partial results.
func WithDiffFilter(filter func(*EntryDiff) (bool, error)) DiffOptionsFunc {
	return func(options *DiffOptions) { options.FilterFunc = filter }
}

func collectDiffOptions(opts []DiffOptionsFunc) DiffOptions {
	var options DiffOptions
	for _, opt := range opts {
		opt(&options)
	}
	return options
}
