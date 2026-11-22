package snapshot

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/egezamb/achilles-fleet-server/internal/vdb"
)

// retryAfter is how long Refresh waits after a failed build before it tries
// again, or the interval itself when that is shorter. OSV being down for a
// while is normal; the file already there keeps being served meanwhile.
const retryAfter = 15 * time.Minute

// buildTimeout bounds one build, as build-vdb's -timeout does.
const buildTimeout = 5 * time.Minute

// Due returns how long until the snapshot at path is older than every: zero
// when it already is, or when there is no snapshot the server would serve.
// It reads the age from generated_at, not the file's mtime, so a restart does
// not rebuild a snapshot that is still fresh.
func Due(path string, every time.Duration, now time.Time) time.Duration {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	info, err := vdb.Validate(b)
	if err != nil {
		return 0
	}
	return max(info.GeneratedAt.Add(every).Sub(now), 0)
}

// Refresh keeps the snapshot at path no older than every, rebuilding it with
// build, until ctx is done. A failed build leaves the file as it was and is
// retried after 15 minutes.
func Refresh(ctx context.Context, path string, every time.Duration, build func(context.Context) (Snapshot, error)) {
	refresh(ctx, path, every, min(every, retryAfter), build)
}

func refresh(ctx context.Context, path string, every, retry time.Duration, build func(context.Context) (Snapshot, error)) {
	for {
		if !sleep(ctx, Due(path, every, time.Now())) {
			return
		}
		if err := rebuild(ctx, path, build); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("vdb snapshot rebuild failed, keeping the current file", "path", path, "err", err)
			if !sleep(ctx, retry) {
				return
			}
		}
	}
}

func rebuild(ctx context.Context, path string, build func(context.Context) (Snapshot, error)) error {
	ctx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()
	s, err := build(ctx)
	if err != nil {
		return err
	}
	info, err := Write(path, s)
	if err != nil {
		return err
	}
	slog.Info("vdb snapshot rebuilt", "path", path, "products", info.Products, "advisories", info.Advisories)
	return nil
}

// sleep waits for d and reports whether ctx is still live.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
