package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/batch"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/ref"
	"github.com/treeverse/lakefs/pkg/ident"
	"github.com/treeverse/lakefs/pkg/kv"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func newGCReferencesTaskTest(t *testing.T) (*Catalog, *graveler.RepositoryRecord, *Task, *gcReferencesState) {
	t.Helper()
	store, c, repo := setupTaskTest(t)
	c.KVStoreLimited = store
	c.gcRepositoryReader = func(ctx context.Context, id graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
		return c.Store.GetRepository(ctx, id)
	}
	c.ownership = newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{
		"test-storage": s3OwnershipStorage("https://objects.example", ""),
	}})
	repo.InstanceUID = "original-instance"
	target, err := c.GCTargetDescriptor(gcReferencesRepository(repo))
	require.NoError(t, err)
	now := time.Now().UTC()
	task := &Task{Id: NewTaskID(GCReferencesTaskPrefix), Operation: OpGCReferences, OwnerInstanceId: c.instanceID, UpdatedAt: timestamppb.New(now)}
	state := &gcReferencesState{Deadline: now.Add(GCReferencesLifetime), Manifest: GCReferencesManifest{
		SchemaVersion: GCReferencesSchemaVersion, RunID: task.Id, TaskID: task.Id, Scope: GCReferencesScope,
		RepositoryID: repo.RepositoryID.String(), RepositoryInstanceUID: repo.InstanceUID,
		StorageID: repo.StorageID.String(), StorageNamespace: repo.StorageNamespace.String(),
		OwnershipFingerprint: c.GCOwnershipFingerprint(), OwnershipResolverVersion: GCOwnershipResolverVersion, Target: target,
		StartedAt: now, CutoffTime: now.Add(-24 * time.Hour), MinimumAgeSeconds: 86400,
		Parts: []GCReferencesPart{}, Sources: []GCReferencesSource{},
	}}
	require.NoError(t, c.writeGCReferencesTask(t.Context(), repo, task, state, nil))
	return c, repo, task, state
}

func gcReferencesCompletedTestManifest(t *testing.T, state *gcReferencesState) (GCReferencesManifest, *GCReferencesResult) {
	t.Helper()
	manifest := state.Manifest
	manifest.CompletedAt = time.Now().UTC()
	manifest.ExpiresAt = manifest.CompletedAt.Add(GCReferencesLifetime)
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	return manifest, &GCReferencesResult{ManifestLocation: "s3://test-bucket/_lakefs/references/manifest.json", ManifestSHA256: gcReferencesDigest(data), ExpiresAt: manifest.ExpiresAt}
}

func TestGCReferencesTaskTerminalCAS(t *testing.T) {
	t.Parallel()
	c, repo, task, state := newGCReferencesTaskTest(t)
	manifest, result := gcReferencesCompletedTestManifest(t, state)
	start := make(chan struct{})
	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest)
			if err == nil {
				successes.Add(1)
			} else {
				require.ErrorIs(t, err, ErrGCReferencesStopped)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.NoError(t, err)
	require.True(t, status.Task.Done)
	require.Equal(t, result, status.Result)
	require.ErrorIs(t, c.failGCReferencesTask(t.Context(), repo, task.Id, errors.New("late failure")), ErrGCReferencesStopped)
	require.NoError(t, c.KVStore.Delete(t.Context(), []byte(graveler.RepoPartition(repo)), []byte(TaskPath(task.Id))))
	require.ErrorIs(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest), graveler.ErrNotFound)
	var record GCReferencesTaskData
	_, err = GetTaskStatus(t.Context(), c.KVStore, repo, task.Id, &record)
	require.ErrorIs(t, err, graveler.ErrNotFound, "late completion must never recreate a deleted task")
}

func TestGCReferencesTaskRejectsChangedProof(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*GCReferencesManifest, *GCReferencesResult)
	}{
		{"cutoff", func(m *GCReferencesManifest, _ *GCReferencesResult) { m.CutoffTime = m.CutoffTime.Add(time.Second) }},
		{"age", func(m *GCReferencesManifest, _ *GCReferencesResult) { m.MinimumAgeSeconds++ }},
		{"target", func(m *GCReferencesManifest, _ *GCReferencesResult) { m.Target.Bucket = "other-bucket" }},
		{"started", func(m *GCReferencesManifest, _ *GCReferencesResult) { m.StartedAt = m.StartedAt.Add(time.Second) }},
		{"scope", func(m *GCReferencesManifest, _ *GCReferencesResult) { m.Scope = "repository" }},
		{"checksum", func(_ *GCReferencesManifest, r *GCReferencesResult) { r.ManifestSHA256 = "incorrect" }},
		{"expiry", func(_ *GCReferencesManifest, r *GCReferencesResult) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, repo, task, state := newGCReferencesTaskTest(t)
			manifest, result := gcReferencesCompletedTestManifest(t, state)
			test.change(&manifest, result)
			require.ErrorIs(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest), ErrGCReferencesInvalid)
			persisted, _, _, err := c.readGCReferencesTask(t.Context(), repo, task.Id)
			require.NoError(t, err)
			require.False(t, persisted.Done)
		})
	}
}

func TestGCReferencesTaskStatusExpiration(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{"lease", "deadline"} {
		t.Run(reason, func(t *testing.T) {
			c, repo, task, state := newGCReferencesTaskTest(t)
			manifest, result := gcReferencesCompletedTestManifest(t, state)
			require.NoError(t, c.mutateGCReferencesTask(t.Context(), repo, task.Id, func(task *Task, state *gcReferencesState) error {
				if reason == "lease" {
					task.UpdatedAt = timestamppb.New(time.Now().Add(-time.Minute))
				} else {
					state.Deadline = time.Now().Add(-time.Second)
				}
				return nil
			}))
			status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
			require.NoError(t, err)
			require.True(t, status.Task.Done)
			require.NotEmpty(t, status.Task.ErrorMsg)
			require.Nil(t, status.Result)
			require.ErrorIs(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest), ErrGCReferencesStopped)
		})
	}
	t.Run("refreshed observation", func(t *testing.T) {
		c, repo, task, _ := newGCReferencesTaskTest(t)
		require.ErrorIs(t, c.expireGCReferencesTask(t.Context(), repo, task.Id), ErrGCReferencesStopped)
		persisted, _, _, err := c.readGCReferencesTask(t.Context(), repo, task.Id)
		require.NoError(t, err)
		require.False(t, persisted.Done, "a refreshed lease must survive an old observer's expiration request")
	})
}

func TestGCReferencesTaskCleanupAndBinding(t *testing.T) {
	t.Parallel()
	c, repo, task, state := newGCReferencesTaskTest(t)
	manifest, result := gcReferencesCompletedTestManifest(t, state)
	require.NoError(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest))
	// Generic cleanup uses result expiration, not the old task timestamp heuristic.
	require.NoError(t, c.mutateGCReferencesTask(t.Context(), repo, task.Id, func(task *Task, _ *gcReferencesState) error {
		task.UpdatedAt = timestamppb.New(time.Now().Add(-2 * GCReferencesLifetime))
		return nil
	}))
	require.NoError(t, c.deleteRepositoryExpiredTasks(t.Context(), repo))
	_, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.NoError(t, err)
	c.ownership = newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{
		"test-storage": s3OwnershipStorage("https://changed.example", ""),
	}})
	_, err = c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.ErrorIs(t, err, ErrGCReferencesInvalid)
	c.ownership = newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{
		"test-storage": s3OwnershipStorage("https://objects.example", ""),
	}})
	require.NoError(t, c.mutateGCReferencesTask(t.Context(), repo, task.Id, func(_ *Task, state *gcReferencesState) error {
		state.RecordExpiresAt = time.Now().Add(-time.Second)
		return nil
	}))
	_, err = c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.ErrorIs(t, err, ErrGCReferencesExpired)
	require.NoError(t, c.deleteRepositoryExpiredTasks(t.Context(), repo))
	_, _, _, err = c.readGCReferencesTask(t.Context(), repo, task.Id)
	require.ErrorIs(t, err, graveler.ErrNotFound)
}

func TestGCReferencesLeaseCancellation(t *testing.T) {
	t.Parallel()
	c, repo, task, _ := newGCReferencesTaskTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c.maintainGCReferencesLease(ctx, cancel, repo, task.Id, &gcReferencesProgress{})
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("lease did not release on cancellation")
	}
}

func TestGCReferencesQueuedAndRejectedSubmission(t *testing.T) {
	t.Parallel()
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued cancellation", true: "stopped pool"}[stopped], func(t *testing.T) {
			c, owner, _, _, _ := newGCReferencesScanTest(t)
			poolCtx, cancelPool := context.WithCancel(t.Context())
			defer cancelPool()
			c.workPool = pond.NewPool(1, pond.WithContext(poolCtx))
			if stopped {
				c.workPool.StopAndWait()
			} else {
				started := make(chan struct{})
				c.workPool.Submit(func() { close(started); <-poolCtx.Done() })
				<-started
			}
			taskID, err := c.PrepareGarbageCollectionReferences(t.Context(), owner.RepositoryID.String(), 86400)
			require.NoError(t, err)
			cancelPool()
			c.workPool.StopAndWait()
			require.Eventually(t, func() bool { return c.activeTasks.Load() == 0 }, time.Second, time.Millisecond)
			status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), owner.RepositoryID.String(), taskID)
			require.NoError(t, err)
			require.True(t, status.Task.Done)
			require.NotEmpty(t, status.Task.ErrorMsg)
			require.Nil(t, status.Result)
		})
	}
}

func TestGCReferencesCompletionRejectsChangedInstallation(t *testing.T) {
	t.Parallel()
	for _, changed := range []string{"source mapping", "target reincarnation", "target namespace", "target storage"} {
		t.Run(changed, func(t *testing.T) {
			c, repo, task, state := newGCReferencesTaskTest(t)
			manifest, result := gcReferencesCompletedTestManifest(t, state)
			require.NoError(t, c.validateGCReferencesContext(t.Context(), repo, state))
			if changed == "source mapping" {
				c.ownership = newStorageOwnership(ownershipTestConfig{stores: map[string]config.AdapterConfig{
					"test-storage": s3OwnershipStorage("https://objects.example", ""),
					"source":       s3OwnershipStorage("https://other-objects.example", ""),
				}})
				currentTarget, err := c.GCTargetDescriptor(gcReferencesRepository(repo))
				require.NoError(t, err)
				require.Equal(t, state.Manifest.Target, currentTarget, "source-only mapping change must still invalidate the proof")
			} else {
				replacement := *repo
				copiedRepository := *repo.Repository
				replacement.Repository = &copiedRepository
				switch changed {
				case "target reincarnation":
					replacement.InstanceUID = "replacement-instance"
				case "target namespace":
					replacement.StorageNamespace = "s3://different-bucket"
				case "target storage":
					replacement.StorageID = "different-storage"
				}
				c.Store = &fakeGravelerForTaskTest{repository: &replacement}
			}
			require.ErrorIs(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest), ErrGCReferencesInvalid)
			persisted, persistedState, _, err := c.readGCReferencesTask(t.Context(), repo, task.Id)
			require.NoError(t, err)
			require.False(t, persisted.Done)
			require.Nil(t, persistedState.Result, "changed installation must never acquire an authoritative success proof")
		})
	}
}

func TestGCReferencesLargeManifestHasCompactDurableProof(t *testing.T) {
	t.Parallel()
	c, repo, task, state := newGCReferencesTaskTest(t)
	manifest, result := gcReferencesCompletedTestManifest(t, state)
	for i := range 4000 {
		manifest.Parts = append(manifest.Parts, GCReferencesPart{Location: fmt.Sprintf("s3://test-bucket/%s/%d.parquet", strings.Repeat("prefix", 20), i), SHA256: strings.Repeat("a", 64), RowCount: 10000, SizeBytes: 100000})
		manifest.Sources = append(manifest.Sources, GCReferencesSource{RepositoryID: fmt.Sprintf("repository-%d", i), RepositoryInstanceUID: strings.Repeat("u", 32), PolicySHA256: strings.Repeat("b", 64), EvaluatedAt: manifest.StartedAt})
	}
	manifest.SourceCount = int64(len(manifest.Sources))
	manifest.TotalRows = int64(len(manifest.Parts) * 10000)
	manifest.EntryCount = manifest.TotalRows
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.Greater(t, len(data), 400<<10, "full manifest must exceed DynamoDB's item limit in this fixture")
	result.ManifestSHA256 = gcReferencesDigest(data)
	require.NoError(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest))
	raw, err := c.KVStore.Get(t.Context(), []byte(graveler.RepoPartition(repo)), []byte(TaskPath(task.Id)))
	require.NoError(t, err)
	require.Less(t, len(raw.Value), 8<<10, "durable proof must not grow with part/source counts")
	_, stored, _, err := c.readGCReferencesTask(t.Context(), repo, task.Id)
	require.NoError(t, err)
	require.Empty(t, stored.Manifest.Parts)
	require.Empty(t, stored.Manifest.Sources)
	require.Equal(t, manifest.TotalRows, stored.Manifest.TotalRows)
	require.Equal(t, manifest.SourceCount, stored.Manifest.SourceCount)
	status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.NoError(t, err)
	require.Equal(t, result, status.Result, "compact record must keep the exact full artifact digest")
}

func TestGCReferencesStoredProofRejectsMutation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*gcReferencesState)
	}{
		{"manifest checksum", func(s *gcReferencesState) { s.Result.ManifestSHA256 = strings.Repeat("f", 64) }},
		{"manifest location", func(s *gcReferencesState) { s.Result.ManifestLocation = "s3://test-bucket/different.json" }},
		{"cutoff", func(s *gcReferencesState) { s.Manifest.CutoffTime = s.Manifest.CutoffTime.Add(-time.Hour) }},
		{"counts", func(s *gcReferencesState) { s.Manifest.TotalRows++ }},
		{"expiry", func(s *gcReferencesState) { s.Manifest.ExpiresAt = s.Manifest.ExpiresAt.Add(time.Hour) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, repo, task, state := newGCReferencesTaskTest(t)
			manifest, result := gcReferencesCompletedTestManifest(t, state)
			require.NoError(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest))
			require.NoError(t, c.mutateGCReferencesTask(t.Context(), repo, task.Id, func(_ *Task, s *gcReferencesState) error { test.change(s); return nil }))
			status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
			require.ErrorIs(t, err, ErrGCReferencesInvalid)
			require.Nil(t, status)
		})
	}
}

func TestGCReferencesStatusRejectsRemovedDeclarationFingerprint(t *testing.T) {
	t.Parallel()
	c, repo, task, state := newGCReferencesTaskTest(t)
	manifest, result := gcReferencesCompletedTestManifest(t, state)
	require.Equal(t, 1, manifest.SchemaVersion)
	require.Equal(t, 1, manifest.OwnershipResolverVersion)
	require.NoError(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest))
	status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.NoError(t, err)
	require.Equal(t, result, status.Result)

	// Freeze the former canonical fingerprint schema, including its field order.
	// A valid compact proof must still be rejected after declaration fields disappear;
	// dropping unknown target JSON fields is not the invalidation mechanism.
	const previousCanonicalMapping = `{"resolver_version":1,"mappings":[{"id":"test-storage",` +
		`"provider":"s3","service":"https://objects.example","identity_basis":"declared_endpoint_bucket",` +
		`"namespace_scope":"endpoint_bucket","routes":["https://objects.example"],"unknown":false}]}`
	previousFingerprint := gcReferencesDigest([]byte(previousCanonicalMapping))
	require.NotEqual(t, c.GCOwnershipFingerprint(), previousFingerprint)

	previousManifest := manifest
	previousManifest.TaskID = NewTaskID(GCReferencesTaskPrefix)
	previousManifest.RunID = previousManifest.TaskID
	previousManifest.OwnershipFingerprint = previousFingerprint
	previousManifest.StartedAt = manifest.StartedAt.Add(-time.Hour)
	previousManifest.CutoffTime = manifest.CutoffTime.Add(-time.Hour)
	previousManifest.CompletedAt = previousManifest.StartedAt.Add(time.Minute)
	previousManifest.ExpiresAt = previousManifest.CompletedAt.Add(GCReferencesLifetime)
	data, err := json.Marshal(previousManifest)
	require.NoError(t, err)
	previousResult := &GCReferencesResult{
		ManifestLocation: "s3://test-bucket/_lakefs/references/previous-manifest.json",
		ManifestSHA256:   gcReferencesDigest(data),
		ExpiresAt:        previousManifest.ExpiresAt,
	}
	require.NoError(t, validateGCReferencesResult(previousManifest, previousResult))
	previousState := &gcReferencesState{
		Manifest:        compactGCReferencesManifest(previousManifest),
		Deadline:        previousManifest.StartedAt.Add(GCReferencesLifetime),
		RecordExpiresAt: previousResult.ExpiresAt,
		Result:          previousResult,
	}
	previousState.ResultBindingSHA256, err = gcReferencesResultBinding(previousState.Manifest, previousResult)
	require.NoError(t, err)
	previousTask := &Task{
		Id: previousManifest.TaskID, Operation: OpGCReferences, OwnerInstanceId: c.instanceID,
		Done: true, UpdatedAt: timestamppb.New(previousManifest.CompletedAt),
	}
	require.NoError(t, c.writeGCReferencesTask(t.Context(), repo, previousTask, previousState, nil))
	_, persisted, _, err := c.readGCReferencesTask(t.Context(), repo, previousTask.Id)
	require.NoError(t, err)
	require.NoError(t, validateGCReferencesStoredResult(persisted), "the earlier proof must remain internally valid")

	status, err = c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), previousTask.Id)
	require.ErrorIs(t, err, ErrGCReferencesInvalid)
	require.Nil(t, status)
	status, err = c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.NoError(t, err)
	require.Equal(t, result, status.Result, "fresh protocol-v1 preparations remain usable")
}

func TestGCReferencesTaskSizeAndErrorBounds(t *testing.T) {
	t.Parallel()
	c, repo, task, state := newGCReferencesTaskTest(t)
	tooLarge := *state
	tooLarge.Manifest.Target.Routes = []string{strings.Repeat("x", gcReferencesMaxTaskBytes)}
	require.ErrorIs(t, c.writeGCReferencesTask(t.Context(), repo, task, &tooLarge, nil), errGCReferencesLimitExceeded)
	require.NoError(t, c.failGCReferencesTask(t.Context(), repo, task.Id, errors.New(strings.Repeat("é", gcReferencesMaxTaskBytes))))
	status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
	require.NoError(t, err)
	require.True(t, status.Task.Done)
	require.LessOrEqual(t, len(status.Task.ErrorMsg), gcReferencesMaxErrorBytes)
	require.Nil(t, status.Result)
}

type gcReferencesReaderStorageConfig struct{ config.StorageConfig }

func (gcReferencesReaderStorageConfig) ResolveStoredRepositoryStorageID(id string) (string, error) {
	return id, nil
}

type gcReferencesCachedRepositoryStore struct {
	Store
	reader *ref.Manager
}

func (s *gcReferencesCachedRepositoryStore) GetRepository(ctx context.Context, id graveler.RepositoryID) (*graveler.RepositoryRecord, error) {
	return s.reader.GetRepository(ctx, id)
}

func TestGCReferencesRejectsRecreatedTargetWithWarmReplicaCache(t *testing.T) {
	t.Parallel()
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprint(completed), func(t *testing.T) {
			c, repo, task, state := newGCReferencesTaskTest(t)
			managerConfig := ref.ManagerConfig{KVStore: c.KVStore, KVStoreLimited: c.KVStore, Executor: batch.NopExecutor(), AddressProvider: ident.NewHexAddressProvider(), RepositoryCacheConfig: ref.CacheConfig{Size: 10, Expiry: time.Hour}}
			validatingNode := ref.NewRefManager(managerConfig, gcReferencesReaderStorageConfig{})
			replacingNode := ref.NewRefManager(managerConfig, gcReferencesReaderStorageConfig{})
			_, err := replacingNode.CreateBareRepository(t.Context(), repo.RepositoryID, *repo.Repository)
			require.NoError(t, err)
			cached, err := validatingNode.GetRepository(t.Context(), repo.RepositoryID)
			require.NoError(t, err)
			require.Equal(t, repo.InstanceUID, cached.InstanceUID)
			c.Store = &gcReferencesCachedRepositoryStore{Store: c.Store, reader: validatingNode}
			c.gcRepositoryReader = validatingNode.GetRepositoryUncached
			manifest, result := gcReferencesCompletedTestManifest(t, state)
			if completed {
				require.NoError(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest))
			}
			require.NoError(t, replacingNode.DeleteRepository(t.Context(), repo.RepositoryID))
			replacement := *repo.Repository
			replacement.InstanceUID = "replacement-on-other-node"
			_, err = replacingNode.CreateBareRepository(t.Context(), repo.RepositoryID, replacement)
			require.NoError(t, err)
			stillCached, err := c.Store.GetRepository(t.Context(), repo.RepositoryID)
			require.NoError(t, err)
			require.Equal(t, repo.InstanceUID, stillCached.InstanceUID, "ordinary repository cache must remain warm with the old incarnation")
			current, err := replacingNode.GetRepositoryUncached(t.Context(), repo.RepositoryID)
			require.NoError(t, err)
			require.Equal(t, replacement.InstanceUID, current.InstanceUID)
			status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
			require.ErrorIs(t, err, graveler.ErrNotFound, "status must read the new instance partition, never the cached successful old proof")
			require.Nil(t, status)
			if !completed {
				require.ErrorIs(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest), ErrGCReferencesInvalid)
			}
		})
	}
}

func TestGCReferencesFailureRequiresCurrentWorkerOwner(t *testing.T) {
	t.Parallel()
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			c, repo, task, _ := newGCReferencesTaskTest(t)
			const currentOwner = "replacement-worker"
			require.NoError(t, c.mutateGCReferencesTask(t.Context(), repo, task.Id, func(task *Task, _ *gcReferencesState) error {
				task.OwnerInstanceId = currentOwner
				return nil
			}))
			require.ErrorIs(t, c.failGCReferencesTask(t.Context(), repo, task.Id, cause), ErrGCReferencesStopped)
			running, state, _, err := c.readGCReferencesTask(t.Context(), repo, task.Id)
			require.NoError(t, err)
			require.False(t, running.Done, "a previous worker owner cannot fail the current owner's running task")
			require.Empty(t, running.ErrorMsg)
			require.Equal(t, currentOwner, running.OwnerInstanceId)
			require.Nil(t, state.Result)
			currentWorker := &Catalog{KVStore: c.KVStore, instanceID: currentOwner}
			require.NoError(t, currentWorker.failGCReferencesTask(t.Context(), repo, task.Id, cause))
			failed, state, _, err := c.readGCReferencesTask(t.Context(), repo, task.Id)
			require.NoError(t, err)
			require.True(t, failed.Done)
			require.Equal(t, cause.Error(), failed.ErrorMsg)
			require.Nil(t, state.Result)
		})
	}
}

func TestGCReferencesTargetMustRemainWritable(t *testing.T) {
	t.Parallel()
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprint(completed), func(t *testing.T) {
			c, repo, task, state := newGCReferencesTaskTest(t)
			manifest, result := gcReferencesCompletedTestManifest(t, state)
			require.NoError(t, c.validateGCReferencesContext(t.Context(), repo, state))
			if completed {
				require.NoError(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest))
			}
			current := *repo
			metadata := *repo.Repository
			metadata.ReadOnly = true
			current.Repository = &metadata
			c.Store = &fakeGravelerForTaskTest{repository: &current}
			status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), repo.RepositoryID.String(), task.Id)
			require.ErrorIs(t, err, graveler.ErrReadOnlyRepository)
			require.Nil(t, status, "a read-only target cannot expose a usable deletion proof")
			if !completed {
				require.ErrorIs(t, c.finishGCReferencesTask(t.Context(), repo, task.Id, result, manifest), graveler.ErrReadOnlyRepository)
				running, persisted, _, err := c.readGCReferencesTask(t.Context(), repo, task.Id)
				require.NoError(t, err)
				require.False(t, running.Done)
				require.Nil(t, persisted.Result)
			}
		})
	}
}

type gcReferencesRejectSuccessStore struct {
	kv.Store
	rejected atomic.Int64
}

func (s *gcReferencesRejectSuccessStore) SetIf(ctx context.Context, partition, key, value []byte, predicate kv.Predicate) error {
	var record GCReferencesTaskData
	if err := proto.Unmarshal(value, &record); err == nil && record.Task != nil && record.Task.Operation == OpGCReferences && record.Task.Done && record.Task.ErrorMsg == "" {
		s.rejected.Add(1)
		return errGCReferencesTest
	}
	return s.Store.SetIf(ctx, partition, key, value, predicate)
}

func TestGCReferencesSuccessPersistenceFailure(t *testing.T) {
	t.Parallel()
	fixture, owner, _, store, adapter := newGCReferencesScanTest(t)
	rejectingKV := &gcReferencesRejectSuccessStore{Store: fixture.KVStore}
	// Keep the fixture's unrelated heartbeat on its original Catalog; the worker
	// under test uses this independent instance and the failure-injecting KV store.
	c := &Catalog{
		Store: store, BlockAdapter: adapter, KVStore: rejectingKV, KVStoreLimited: fixture.KVStoreLimited,
		workPool: fixture.workPool, instanceID: fixture.instanceID, ownership: fixture.ownership,
		gcReferencesRefs: fixture.gcReferencesRefs, gcRepositoryReader: store.GetRepository,
	}
	taskID, err := c.PrepareGarbageCollectionReferences(t.Context(), owner.RepositoryID.String(), 86400)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return c.activeTasks.Load() == 0 }, 5*time.Second, time.Millisecond)
	require.EqualValues(t, 1, rejectingKV.rejected.Load(), "fault must reject the final successful CAS, after all uploads")
	status, err := c.GetGarbageCollectionReferencesStatus(t.Context(), owner.RepositoryID.String(), taskID)
	require.NoError(t, err)
	require.True(t, status.Task.Done)
	require.Equal(t, errGCReferencesTest.Error(), status.Task.ErrorMsg)
	require.Nil(t, status.Result, "uploaded artifacts cannot substitute for authoritative successful task persistence")
	require.Len(t, adapter.objects, 2)
	manifestUploaded := false
	for location := range adapter.objects {
		manifestUploaded = manifestUploaded || strings.HasSuffix(location, "manifest.json")
	}
	require.True(t, manifestUploaded, "fixture must fail after the full manifest has been uploaded")
	_, state, _, err := c.readGCReferencesTask(t.Context(), owner, taskID)
	require.NoError(t, err)
	require.Nil(t, state.Result)
	require.Empty(t, state.ResultBindingSHA256)
}
