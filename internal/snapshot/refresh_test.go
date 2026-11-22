package snapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egezamb/achilles-fleet-server/internal/osv"
)

// builder returns a build func that makes a valid snapshot generated at the
// time of the call, or fails while failing is set, and counts calls.
func builder(failing *atomic.Bool, calls *atomic.Int32) func(context.Context) (Snapshot, error) {
	fetch := func(ctx context.Context, eco, name string) ([]osv.Vuln, error) {
		if name == "electron" {
			return []osv.Vuln{record("GHSA-1", semverRange(ev("introduced", "0"), ev("fixed", "1.0.0")))}, nil
		}
		return nil, nil
	}
	return func(ctx context.Context) (Snapshot, error) {
		calls.Add(1)
		if failing != nil && failing.Load() {
			return Snapshot{}, errors.New("osv down")
		}
		return Build(ctx, fetch, Products, time.Now())
	}
}

// start runs refresh in the background and returns a func that stops it and
// waits for it to return, registered as a cleanup too.
func start(t *testing.T, path string, every, retry time.Duration, build func(context.Context) (Snapshot, error)) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { refresh(ctx, path, every, retry, build); close(done) }()
	stop = func() { cancel(); <-done }
	t.Cleanup(stop)
	return stop
}

func writeAt(t *testing.T, path string, generated time.Time) {
	t.Helper()
	var calls atomic.Int32
	s, err := builder(nil, &calls)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.GeneratedAt = generated.Unix()
	if _, err := Write(path, s); err != nil {
		t.Fatal(err)
	}
}

func TestDueReadsTheAgeFromTheSnapshot(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	if d := Due(filepath.Join(dir, "missing.json"), 24*time.Hour, now); d != 0 {
		t.Errorf("missing file: due in %s, want now", d)
	}

	fresh := filepath.Join(dir, "fresh.json")
	writeAt(t, fresh, now.Add(-time.Hour))
	if d := Due(fresh, 24*time.Hour, now); d != 23*time.Hour {
		t.Errorf("an hour old: due in %s, want 23h", d)
	}

	old := filepath.Join(dir, "old.json")
	writeAt(t, old, now.Add(-25*time.Hour))
	if d := Due(old, 24*time.Hour, now); d != 0 {
		t.Errorf("25 hours old: due in %s, want now", d)
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if d := Due(broken, 24*time.Hour, now); d != 0 {
		t.Errorf("a file the server refuses: due in %s, want now", d)
	}
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRefreshBuildsAMissingSnapshotOnceAndThenWaits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vdb.json")
	var calls atomic.Int32
	stop := start(t, path, 24*time.Hour, time.Millisecond, builder(nil, &calls))

	waitFor(t, "the first build", func() bool { return Due(path, 24*time.Hour, time.Now()) > 0 })
	time.Sleep(50 * time.Millisecond)
	stop()
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d builds, want 1: a fresh snapshot must not be rebuilt", n)
	}
}

func TestRefreshLeavesAFreshSnapshotAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vdb.json")
	writeAt(t, path, time.Now().Add(-time.Hour))
	var calls atomic.Int32
	stop := start(t, path, 24*time.Hour, time.Millisecond, builder(nil, &calls))

	time.Sleep(50 * time.Millisecond)
	stop()
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d builds after a restart with a fresh snapshot, want 0", n)
	}
}

func TestRefreshRetriesAFailedBuildAndKeepsTheOldFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vdb.json")
	writeAt(t, path, time.Now().Add(-48*time.Hour))
	before, _ := os.ReadFile(path)
	var failing atomic.Bool
	failing.Store(true)
	var calls atomic.Int32
	start(t, path, 24*time.Hour, time.Millisecond, builder(&failing, &calls))

	waitFor(t, "a retry after a failed build", func() bool { return calls.Load() >= 2 })
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a failed build changed the snapshot file")
	}
	failing.Store(false)
	waitFor(t, "a successful build once OSV is back", func() bool { return Due(path, 24*time.Hour, time.Now()) > 0 })
}

func TestRefreshStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	Refresh(ctx, filepath.Join(t.TempDir(), "vdb.json"), time.Hour, builder(nil, &calls))
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d builds with a cancelled context, want 0", n)
	}
}
