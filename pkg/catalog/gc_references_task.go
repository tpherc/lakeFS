package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/validator"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrGCReferencesExpired = errors.New("garbage collection reference result expired")
	ErrGCReferencesInvalid = errors.New("garbage collection reference context mismatch")
	ErrGCReferencesStopped = errors.New("garbage collection reference task is no longer running")
)

const gcReferencesLeaseTimeout = 30 * time.Second
const gcReferencesCASAttempts = 8
const gcReferencesMaxTaskBytes = 256 << 10
const gcReferencesMaxErrorBytes = 4096
const gcReferencesTaskFailureReserve = 32 << 10

// The JSON payload is wrapped in GCReferencesTaskData so generic task readers can
// recognize it, while all writes and expiration use this operation's CAS protocol.
type gcReferencesState struct {
	Manifest            GCReferencesManifest `json:"manifest"`
	ResultBindingSHA256 string               `json:"result_binding_sha256,omitempty"`
	Deadline            time.Time            `json:"deadline"`
	RecordExpiresAt     time.Time            `json:"record_expires_at"`
	Result              *GCReferencesResult  `json:"result,omitempty"`
}

type gcReferencesProgress struct {
	entries atomic.Int64
}

func (c *Catalog) PrepareGarbageCollectionReferences(ctx context.Context, repositoryID string, minimumAgeSeconds int64) (string, error) {
	if err := validator.Validate([]validator.ValidateArg{{Name: "repository", Value: repositoryID, Fn: graveler.ValidateRepositoryID}}); err != nil {
		return "", err
	}
	if minimumAgeSeconds < 1 || minimumAgeSeconds > math.MaxInt64/int64(time.Second) {
		return "", fmt.Errorf("minimum age seconds out of range: %w", graveler.ErrInvalidValue)
	}
	repo, err := c.readGCReferencesRepository(ctx, graveler.RepositoryID(repositoryID))
	if err != nil {
		return "", err
	}
	if repo.ReadOnly {
		return "", graveler.ErrReadOnlyRepository
	}
	target, err := c.GCTargetDescriptor(gcReferencesRepository(repo))
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	taskID := NewTaskID(GCReferencesTaskPrefix)
	state := &gcReferencesState{
		Manifest: GCReferencesManifest{
			SchemaVersion: GCReferencesSchemaVersion, RunID: taskID, TaskID: taskID, Scope: GCReferencesScope,
			RepositoryID: repositoryID, RepositoryInstanceUID: repo.InstanceUID,
			StorageID: repo.StorageID.String(), StorageNamespace: repo.StorageNamespace.String(),
			OwnershipFingerprint: c.GCOwnershipFingerprint(), OwnershipResolverVersion: GCOwnershipResolverVersion, Target: target,
			StartedAt: now, CutoffTime: now.Add(-time.Duration(minimumAgeSeconds) * time.Second), MinimumAgeSeconds: minimumAgeSeconds,
			Parts: []GCReferencesPart{}, Sources: []GCReferencesSource{},
		},
		Deadline: now.Add(GCReferencesLifetime),
	}
	task := &Task{Id: taskID, Operation: OpGCReferences, OwnerInstanceId: c.instanceID, UpdatedAt: timestamppb.New(now)}
	if err := c.writeGCReferencesTask(ctx, repo, task, state, nil); err != nil {
		return "", err
	}
	workerCtx, cancel := context.WithDeadline(c.workPool.Context(), state.Deadline)
	progress := &gcReferencesProgress{}
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		c.maintainGCReferencesLease(workerCtx, cancel, repo, taskID, progress)
	}()
	c.activeTasks.Add(1)
	job := c.workPool.SubmitErr(func() error {
		if err := workerCtx.Err(); err != nil {
			return err
		}
		result, err := c.prepareGCReferenceArtifacts(workerCtx, repo, &state.Manifest, progress)
		if err != nil {
			return err
		}
		if err := workerCtx.Err(); err != nil {
			return err
		}
		return c.finishGCReferencesTask(workerCtx, repo, taskID, result, state.Manifest)
	})
	// The pool may reject submission or cancel a queued task without invoking it.
	// Supervision therefore owns the lease and counter outside the worker closure.
	go func() {
		defer c.activeTasks.Add(-1)
		var err error
		select {
		case <-job.Done():
			err = job.Wait()
		case <-workerCtx.Done():
			err = workerCtx.Err()
		}
		cancel()
		<-leaseDone
		if err == nil {
			return
		}
		failureCtx, failureCancel := context.WithTimeout(context.Background(), gcReferencesLeaseTimeout)
		defer failureCancel()
		if failureErr := c.failGCReferencesTask(failureCtx, repo, taskID, err); failureErr != nil && !errors.Is(failureErr, ErrGCReferencesStopped) {
			c.log(failureCtx).WithError(failureErr).Error("Failed to persist GC reference task failure")
		}
	}()

	return taskID, nil
}

func (c *Catalog) readGCReferencesRepository(ctx context.Context, id graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	if c.gcRepositoryReader == nil {
		return nil, fmt.Errorf("authoritative GC repository reader is not configured: %w", ErrGCReferencesInvalid)
	}
	return c.gcRepositoryReader(ctx, id)
}

func gcReferencesRepository(repo *graveler.RepositoryRecord) *Repository {
	return &Repository{Name: repo.RepositoryID.String(), StorageID: repo.StorageID.String(), StorageNamespace: repo.StorageNamespace.String(), ReadOnly: repo.ReadOnly}
}

func (c *Catalog) writeGCReferencesTask(ctx context.Context, repo *graveler.RepositoryRecord, task *Task, state *gcReferencesState, predicate kv.Predicate) error {
	// Full part lists and source provenance belong only to the uploaded manifest.
	// Bound the complete protobuf envelope below the smallest supported KV item limit.
	compactState := *state
	compactState.Manifest = compactGCReferencesManifest(state.Manifest)
	data, err := json.Marshal(&compactState)
	if err != nil {
		return err
	}
	record := &GCReferencesTaskData{Task: task, Data: data}
	limit := gcReferencesMaxTaskBytes
	if !task.Done {
		// JSON escaping can expand a bounded error string. Leave room so an
		// accepted running task can always persist its terminal failure.
		limit -= gcReferencesTaskFailureReserve
	}
	if proto.Size(record) > limit {
		return fmt.Errorf("task record bytes: %w", errGCReferencesLimitExceeded)
	}
	return kv.SetMsgIf(ctx, c.KVStore, graveler.RepoPartition(repo), []byte(TaskPath(task.Id)), record, predicate)
}

func (c *Catalog) readGCReferencesTask(ctx context.Context, repo *graveler.RepositoryRecord, taskID string) (*Task, *gcReferencesState, kv.Predicate, error) {
	if !IsTaskID(GCReferencesTaskPrefix, taskID) {
		return nil, nil, nil, graveler.ErrNotFound
	}
	var record GCReferencesTaskData
	predicate, err := GetTaskStatus(ctx, c.KVStore, repo, taskID, &record)
	if err != nil {
		return nil, nil, nil, err
	}
	var state gcReferencesState
	if err := json.Unmarshal(record.Data, &state); err != nil {
		return nil, nil, nil, fmt.Errorf("decode reference task: %w", err)
	}
	if record.Task == nil || record.Task.Id != taskID || record.Task.Operation != OpGCReferences || state.Manifest.TaskID != taskID || state.Manifest.RunID != taskID || state.Manifest.RepositoryID != repo.RepositoryID.String() || state.Manifest.RepositoryInstanceUID != repo.InstanceUID {
		return nil, nil, nil, ErrGCReferencesInvalid
	}
	return record.Task, &state, predicate, nil
}

func (c *Catalog) validateGCReferencesContext(ctx context.Context, repo *graveler.RepositoryRecord, state *gcReferencesState) error {
	current, err := c.readGCReferencesRepository(ctx, repo.RepositoryID)
	if err != nil {
		return err
	}
	if current.ReadOnly {
		return graveler.ErrReadOnlyRepository
	}
	m := &state.Manifest
	if current.InstanceUID != m.RepositoryInstanceUID || current.StorageID.String() != m.StorageID || current.StorageNamespace.String() != m.StorageNamespace || m.OwnershipFingerprint != c.GCOwnershipFingerprint() {
		return ErrGCReferencesInvalid
	}
	target, err := c.GCTargetDescriptor(gcReferencesRepository(current))
	if err != nil {
		return err
	}
	want, err := json.Marshal(m.Target)
	if err != nil {
		return err
	}
	got, err := json.Marshal(target)
	if err != nil {
		return err
	}
	if string(want) != string(got) || m.Scope != GCReferencesScope || m.SchemaVersion != GCReferencesSchemaVersion || m.OwnershipResolverVersion != GCOwnershipResolverVersion {
		return ErrGCReferencesInvalid
	}
	return nil
}

func gcReferencesStopped(task *Task, state *gcReferencesState, now time.Time) bool {
	return task.Done || !now.Before(state.Deadline) || task.UpdatedAt == nil || now.Sub(task.UpdatedAt.AsTime()) > gcReferencesLeaseTimeout
}

func (c *Catalog) mutateGCReferencesTask(ctx context.Context, repo *graveler.RepositoryRecord, taskID string, change func(*Task, *gcReferencesState) error) error {
	for range gcReferencesCASAttempts {
		task, state, predicate, err := c.readGCReferencesTask(ctx, repo, taskID)
		if err != nil {
			return err
		}
		if err := change(task, state); err != nil {
			return err
		}
		if err := c.writeGCReferencesTask(ctx, repo, task, state, predicate); !errors.Is(err, kv.ErrPredicateFailed) {
			return err
		}
	}
	return fmt.Errorf("update reference task: %w", kv.ErrPredicateFailed)
}

func (c *Catalog) maintainGCReferencesLease(ctx context.Context, cancel context.CancelFunc, repo *graveler.RepositoryRecord, taskID string, progress *gcReferencesProgress) {
	ticker := time.NewTicker(TaskHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := c.mutateGCReferencesTask(ctx, repo, taskID, func(task *Task, state *gcReferencesState) error {
				now := time.Now().UTC()
				if task.OwnerInstanceId != c.instanceID || gcReferencesStopped(task, state, now) {
					return ErrGCReferencesStopped
				}
				task.UpdatedAt = timestamppb.New(now)
				task.Progress = progress.entries.Load()
				return nil
			})
			if err != nil {
				cancel()
				return
			}
		}
	}
}

func (c *Catalog) finishGCReferencesTask(ctx context.Context, repo *graveler.RepositoryRecord, taskID string, result *GCReferencesResult, manifest GCReferencesManifest) error {
	return c.mutateGCReferencesTask(ctx, repo, taskID, func(task *Task, state *gcReferencesState) error {
		now := time.Now().UTC()
		if task.OwnerInstanceId != c.instanceID || gcReferencesStopped(task, state, now) {
			return ErrGCReferencesStopped
		}
		if err := c.validateGCReferencesContext(ctx, repo, state); err != nil {
			return err
		}
		if !sameGCReferencesSpecification(manifest, state.Manifest) || validateGCReferencesResult(manifest, result) != nil {
			return ErrGCReferencesInvalid
		}
		task.Done = true
		task.UpdatedAt = timestamppb.New(now)
		task.Progress = manifest.EntryCount
		state.Manifest = compactGCReferencesManifest(manifest)
		state.Result = result
		state.RecordExpiresAt = result.ExpiresAt
		binding, err := gcReferencesResultBinding(state.Manifest, result)
		if err != nil {
			return err
		}
		state.ResultBindingSHA256 = binding
		return nil
	})
}

func compactGCReferencesManifest(manifest GCReferencesManifest) GCReferencesManifest {
	manifest.Parts, manifest.Sources = nil, nil
	return manifest
}

// This checksum binds the small durable header/counts to the exact manifest digest
// verified at finalization. Status need not download the potentially large artifact.
func gcReferencesResultBinding(summary GCReferencesManifest, result *GCReferencesResult) (string, error) {
	data, err := json.Marshal(struct {
		Summary GCReferencesManifest `json:"summary"`
		Result  *GCReferencesResult  `json:"result"`
	}{Summary: summary, Result: result})
	if err != nil {
		return "", err
	}
	return gcReferencesDigest(data), nil
}

func validateGCReferencesStoredResult(state *gcReferencesState) error {
	if err := validateGCReferencesResultMetadata(state.Manifest, state.Result); err != nil {
		return err
	}
	if len(state.Manifest.Parts) != 0 || len(state.Manifest.Sources) != 0 || !state.RecordExpiresAt.Equal(state.Manifest.ExpiresAt) {
		return ErrGCReferencesInvalid
	}
	binding, err := gcReferencesResultBinding(state.Manifest, state.Result)
	if err != nil {
		return err
	}
	if binding != state.ResultBindingSHA256 {
		return ErrGCReferencesInvalid
	}
	return nil
}

// Only fields captured at acceptance participate in this comparison. Output fields
// are produced by the worker, while the stored acceptance specification is immutable.
func sameGCReferencesSpecification(a, b GCReferencesManifest) bool {
	clearOutputs := func(m *GCReferencesManifest) {
		m.CompletedAt, m.ExpiresAt = time.Time{}, time.Time{}
		m.Parts, m.Sources = nil, nil
		m.TotalRows, m.SourceCount, m.CommitCount, m.EntryCount = 0, 0, 0, 0
	}
	clearOutputs(&a)
	clearOutputs(&b)
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && string(left) == string(right)
}

func validateGCReferencesResultMetadata(manifest GCReferencesManifest, result *GCReferencesResult) error {
	if result == nil || result.ManifestLocation == "" || manifest.CompletedAt.IsZero() ||
		!manifest.ExpiresAt.Equal(manifest.CompletedAt.Add(GCReferencesLifetime)) ||
		!result.ExpiresAt.Equal(manifest.ExpiresAt) {
		return ErrGCReferencesInvalid
	}
	digest, err := hex.DecodeString(result.ManifestSHA256)
	if err != nil || len(digest) != sha256.Size {
		return ErrGCReferencesInvalid
	}
	return nil
}

func validateGCReferencesResult(manifest GCReferencesManifest, result *GCReferencesResult) error {
	if err := validateGCReferencesResultMetadata(manifest, result); err != nil {
		return err
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if result.ManifestSHA256 != gcReferencesDigest(data) {
		return ErrGCReferencesInvalid
	}
	return nil
}

func markGCReferencesFailed(task *Task, state *gcReferencesState, cause error) {
	now := time.Now().UTC()
	task.Done = true
	task.UpdatedAt = timestamppb.New(now)
	message := cause.Error()
	if len(message) > gcReferencesMaxErrorBytes {
		message = strings.ToValidUTF8(message[:gcReferencesMaxErrorBytes], "")
	}
	task.ErrorMsg = message
	task.StatusCode = http.StatusInternalServerError
	if errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) || errors.Is(cause, ErrGCReferencesStopped) {
		task.StatusCode = http.StatusRequestTimeout
	}
	state.Result = nil
	state.ResultBindingSHA256 = ""
	state.RecordExpiresAt = now.Add(GCReferencesLifetime)
}

// Recheck expiration inside the CAS mutation: a lease may have advanced since the
// caller observed a stale task. A refreshed task must remain running.
func (c *Catalog) expireGCReferencesTask(ctx context.Context, repo *graveler.RepositoryRecord, taskID string) error {
	return c.mutateGCReferencesTask(ctx, repo, taskID, func(task *Task, state *gcReferencesState) error {
		if task.Done || !gcReferencesStopped(task, state, time.Now()) {
			return ErrGCReferencesStopped
		}
		markGCReferencesFailed(task, state, ErrGCReferencesStopped)
		return nil
	})
}

func (c *Catalog) failGCReferencesTask(ctx context.Context, repo *graveler.RepositoryRecord, taskID string, cause error) error {
	return c.mutateGCReferencesTask(ctx, repo, taskID, func(task *Task, state *gcReferencesState) error {
		if task.Done || task.OwnerInstanceId != c.instanceID {
			return ErrGCReferencesStopped
		}
		markGCReferencesFailed(task, state, cause)
		return nil
	})
}

func (c *Catalog) GetGarbageCollectionReferencesStatus(ctx context.Context, repositoryID, taskID string) (*GCReferencesStatus, error) {
	repo, err := c.readGCReferencesRepository(ctx, graveler.RepositoryID(repositoryID))
	if err != nil {
		return nil, err
	}
	task, state, _, err := c.readGCReferencesTask(ctx, repo, taskID)
	if err != nil {
		return nil, err
	}
	if err := c.validateGCReferencesContext(ctx, repo, state); err != nil {
		return nil, err
	}
	if !task.Done && gcReferencesStopped(task, state, time.Now()) {
		if err := c.expireGCReferencesTask(ctx, repo, taskID); err != nil && !errors.Is(err, ErrGCReferencesStopped) {
			return nil, err
		}
		task, state, _, err = c.readGCReferencesTask(ctx, repo, taskID)
		if err != nil {
			return nil, err
		}
	}
	if task.Done && !time.Now().Before(state.RecordExpiresAt) {
		return nil, ErrGCReferencesExpired
	}
	status := &GCReferencesStatus{Task: task}
	if task.Done && task.ErrorMsg == "" {
		if validateGCReferencesStoredResult(state) != nil || !time.Now().Before(state.Result.ExpiresAt) {
			return nil, ErrGCReferencesInvalid
		}
		status.Result = state.Result
	}
	return status, nil
}

func (c *Catalog) cleanupGCReferencesTask(ctx context.Context, repo *graveler.RepositoryRecord, taskID string) error {
	task, state, _, err := c.readGCReferencesTask(ctx, repo, taskID)
	if errors.Is(err, graveler.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !task.Done {
		if gcReferencesStopped(task, state, time.Now()) {
			err := c.expireGCReferencesTask(ctx, repo, taskID)
			if !errors.Is(err, ErrGCReferencesStopped) {
				return err
			}
		}
		return nil
	}
	if time.Now().Before(state.RecordExpiresAt) {
		return nil
	}
	// Terminal records never change, so deleting one cannot race a successful worker update.
	return c.KVStoreLimited.Delete(ctx, []byte(graveler.RepoPartition(repo)), []byte(TaskPath(taskID)))
}
