package retention

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/treeverse/lakefs/pkg/graveler"
)

// ForEachRetainedCommit reads retained history without writing repository metadata.
// A nil policy retains every known commit indefinitely, including dangling commits.
// evaluatedAt fixes retention evaluation independently of scan duration.
func ForEachRetainedCommit(ctx context.Context, refs GCRefManager, repository *graveler.RepositoryRecord, rules *graveler.GarbageCollectionRules, evaluatedAt time.Time, visit func(graveler.CommitID, graveler.MetaRangeID) error) error {
	if rules == nil {
		return forEachKnownCommit(ctx, refs, repository, visit)
	}
	branches, err := refs.GCBranchIterator(ctx, repository)
	if err != nil {
		return err
	}
	commits, err := refs.GCCommitIterator(ctx, repository)
	if err != nil {
		branches.Close()
		return err
	}
	startingPoints := NewGCStartingPointIterator(commits, branches)
	defer startingPoints.Close()
	tempDir, err := os.MkdirTemp("", "lakefs-gc-references-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	getter := &RepositoryCommitGetterAdapter{RefManager: refs, Repository: repository}
	retained, err := getGarbageCollectionCommitsAt(ctx, startingPoints, getter, rules, tempDir, evaluatedAt)
	if err != nil {
		return err
	}
	for commit, metarange := range retained {
		if metarange.Err != nil {
			return fmt.Errorf("retained commit %s: %w", commit, metarange.Err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(commit, metarange.ID); err != nil {
			return err
		}
	}
	return nil
}

func forEachKnownCommit(ctx context.Context, refs GCRefManager, repository *graveler.RepositoryRecord, visit func(graveler.CommitID, graveler.MetaRangeID) error) error {
	it, err := refs.ListCommits(ctx, repository)
	if err != nil {
		return err
	}
	defer it.Close()
	for it.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		commit := it.Value()
		if err := visit(commit.CommitID, commit.MetaRangeID); err != nil {
			return err
		}
	}
	return it.Err()
}
