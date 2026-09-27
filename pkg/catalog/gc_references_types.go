package catalog

import "time"

const (
	GCReferencesTaskPrefix    = "GCR"
	OpGCReferences            = "gc_prepare_references"
	GCReferencesSchemaVersion = 1
	GCReferencesScope         = "installation"
	GCReferencesLifetime      = TaskExpiryTime
)

// GCReferencesResult is usable only while the authoritative task is successful and unexpired.
type GCReferencesResult struct {
	ManifestLocation string    `json:"manifest_location"`
	ManifestSHA256   string    `json:"manifest_sha256"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type GCReferencesStatus struct {
	Task   *Task
	Result *GCReferencesResult
}

type GCReferencesPart struct {
	Location  string `json:"location"`
	SHA256    string `json:"sha256"`
	RowCount  int64  `json:"row_count"`
	SizeBytes int64  `json:"size_bytes"`
}

type GCReferencesSource struct {
	RepositoryID          string    `json:"repository_id"`
	RepositoryInstanceUID string    `json:"repository_instance_uid"`
	PolicySHA256          string    `json:"policy_sha256"`
	NoPolicy              bool      `json:"no_policy"`
	EvaluatedAt           time.Time `json:"evaluated_at"`
}

// GCReferencesManifest binds complete protection inputs to one owner and one age cutoff.
// It is not a snapshot of concurrent writes and is never sufficient without its task record.
type GCReferencesManifest struct {
	SchemaVersion            int                  `json:"schema_version"`
	RunID                    string               `json:"run_id"`
	TaskID                   string               `json:"task_id"`
	Scope                    string               `json:"scope"`
	RepositoryID             string               `json:"repository_id"`
	RepositoryInstanceUID    string               `json:"repository_instance_uid"`
	StorageID                string               `json:"storage_id"`
	StorageNamespace         string               `json:"storage_namespace"`
	OwnershipFingerprint     string               `json:"ownership_fingerprint"`
	OwnershipResolverVersion int                  `json:"ownership_resolver_version"`
	Target                   GCTargetDescriptor   `json:"target"`
	StartedAt                time.Time            `json:"started_at"`
	CutoffTime               time.Time            `json:"cutoff_time"`
	MinimumAgeSeconds        int64                `json:"minimum_age_seconds"`
	CompletedAt              time.Time            `json:"completed_at"`
	ExpiresAt                time.Time            `json:"expires_at"`
	Parts                    []GCReferencesPart   `json:"parts"`
	Sources                  []GCReferencesSource `json:"sources"`
	TotalRows                int64                `json:"total_rows"`
	SourceCount              int64                `json:"source_count"`
	CommitCount              int64                `json:"commit_count"`
	EntryCount               int64                `json:"entry_count"`
}
