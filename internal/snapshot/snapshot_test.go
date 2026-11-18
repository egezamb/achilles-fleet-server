package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egezamb/achilles-fleet-server/internal/osv"
	"github.com/egezamb/achilles-fleet-server/internal/vdb"
)

// record builds an OSV record for npm/electron with the given ranges.
func record(id string, ranges ...osv.Range) osv.Vuln {
	var v osv.Vuln
	v.ID = id
	v.Summary = "Electron: something"
	v.DatabaseSpecific.Severity = "MODERATE"
	a := osv.Affected{Ranges: ranges}
	a.Package.Ecosystem, a.Package.Name = "npm", "electron"
	v.Affected = []osv.Affected{a}
	return v
}

func semverRange(events ...map[string]string) osv.Range {
	return osv.Range{Type: "SEMVER", Events: events}
}

func ev(k, v string) map[string]string { return map[string]string{k: v} }

func str(p *string) string {
	if p == nil {
		return "<null>"
	}
	return *p
}

func TestConvertTakesTheHighestFixAcrossReleaseLines(t *testing.T) {
	// Electron fixes most advisories on several majors at once.
	v := record("GHSA-1",
		semverRange(ev("introduced", "39.0.0"), ev("fixed", "39.8.1")),
		semverRange(ev("introduced", "41.0.0-alpha.1"), ev("fixed", "41.2.0")),
		semverRange(ev("introduced", "40.0.0"), ev("fixed", "40.10.0")),
	)
	a, ok := Convert(v, "npm", "electron")
	if !ok {
		t.Fatal("not converted")
	}
	if str(a.FixedIn) != "41.2.0" {
		t.Fatalf("fixed_in = %s, want 41.2.0", str(a.FixedIn))
	}
}

func TestConvertComparesPrereleasesAsSemver(t *testing.T) {
	v := record("GHSA-1",
		semverRange(ev("introduced", "45.0.0-alpha.1"), ev("fixed", "45.0.0-alpha.6")),
		semverRange(ev("introduced", "44.0.0"), ev("fixed", "44.9.0")),
	)
	a, _ := Convert(v, "npm", "electron")
	if str(a.FixedIn) != "45.0.0-alpha.6" {
		t.Fatalf("fixed_in = %s, want 45.0.0-alpha.6", str(a.FixedIn))
	}
}

func TestConvertLeavesFixedInNullWhenALineIsNotFixed(t *testing.T) {
	cases := map[string]osv.Vuln{
		"introduced only": record("GHSA-1",
			semverRange(ev("introduced", "39.0.0"), ev("fixed", "39.8.1")),
			semverRange(ev("introduced", "40.0.0")),
		),
		"last_affected": record("GHSA-2",
			semverRange(ev("introduced", "0"), ev("last_affected", "40.1.0")),
		),
		"fix is not a version": record("GHSA-3",
			osv.Range{Type: "ECOSYSTEM", Events: []map[string]string{ev("introduced", "0"), ev("fixed", "next")}},
		),
	}
	for name, v := range cases {
		a, ok := Convert(v, "npm", "electron")
		if !ok || a.FixedIn != nil {
			t.Errorf("%s: fixed_in = %s, want null", name, str(a.FixedIn))
		}
	}
}

func TestConvertIgnoresGitRanges(t *testing.T) {
	v := record("RUSTSEC-1",
		osv.Range{Type: "GIT", Events: []map[string]string{ev("introduced", "0"), ev("fixed", "a1b2c3d")}},
		semverRange(ev("introduced", "0"), ev("fixed", "1.5.6")),
	)
	a, _ := Convert(v, "npm", "electron")
	if str(a.FixedIn) != "1.5.6" {
		t.Fatalf("fixed_in = %s, want 1.5.6", str(a.FixedIn))
	}
}

func TestConvertMapsSeverityAsTheAgentDoes(t *testing.T) {
	for in, want := range map[string]string{
		"LOW": "low", "MODERATE": "medium", "medium": "medium", "HIGH": "high",
		" critical ": "critical", "": "<null>", "UNKNOWN": "<null>",
	} {
		v := record("GHSA-1", semverRange(ev("introduced", "0"), ev("fixed", "1.0.0")))
		v.DatabaseSpecific.Severity = in
		a, _ := Convert(v, "npm", "electron")
		if str(a.Severity) != want {
			t.Errorf("severity %q -> %s, want %s", in, str(a.Severity), want)
		}
	}
}

func TestConvertSkipsWithdrawnAndOtherPackages(t *testing.T) {
	v := record("GHSA-1", semverRange(ev("introduced", "0"), ev("fixed", "1.0.0")))
	if _, ok := Convert(v, "npm", "react-native"); ok {
		t.Error("converted a record for another package")
	}
	v.Withdrawn = "2026-11-01T00:00:00Z"
	if _, ok := Convert(v, "npm", "electron"); ok {
		t.Error("converted a withdrawn record")
	}
}

func TestBuildWritesASnapshotTheServerServes(t *testing.T) {
	full := record("GHSA-2", semverRange(ev("introduced", "0"), ev("fixed", "1.0.0")))
	full.Aliases = []string{"CVE-2026-1"}
	full.Published = "2026-10-22T16:47:54Z"
	full.References = []osv.Reference{{URL: "https://example.com/a"}, {URL: ""}}
	bare := record("GHSA-1", semverRange(ev("introduced", "0"), ev("fixed", "2.0.0")))
	bare.DatabaseSpecific.Severity = ""

	fetch := func(ctx context.Context, eco, name string) ([]osv.Vuln, error) {
		if name == "electron" {
			return []osv.Vuln{full, bare}, nil
		}
		return nil, nil
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	s, err := Build(context.Background(), fetch, Products, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vdb.json")
	info, err := Write(path, s)
	if err != nil {
		t.Fatal(err)
	}
	if info.Products != 3 || info.Advisories != 2 || !info.GeneratedAt.Equal(now) {
		t.Fatalf("info %+v, want 3 products, 2 advisories, generated %s", info, now)
	}

	// The server loads it, and the bare record keeps aliases and references as [].
	if _, _, err := vdb.NewFile(path, 0).Current(); err != nil {
		t.Fatalf("server refuses the file: %v", err)
	}
	b, _ := os.ReadFile(path)
	var got Snapshot
	json.Unmarshal(b, &got)
	e := got.Products["electron"]
	if e[0].ID != "GHSA-1" || e[0].Aliases == nil || e[0].References == nil || e[0].Severity != nil {
		t.Fatalf("first electron advisory %+v: want GHSA-1 (sorted), [] lists, null severity", e[0])
	}
	if len(e[1].References) != 1 || str(e[1].Published) != full.Published {
		t.Fatalf("second electron advisory %+v: want one reference and the published date", e[1])
	}
	if strings.Contains(string(b), `"aliases": null`) || strings.Contains(string(b), `"references": null`) {
		t.Fatal("a null list reached the file")
	}
}

func TestBuildFailsWhenAProductFails(t *testing.T) {
	fetch := func(ctx context.Context, eco, name string) ([]osv.Vuln, error) {
		if name == "tauri" {
			return nil, errors.New("osv down")
		}
		return nil, nil
	}
	if _, err := Build(context.Background(), fetch, Products, time.Now()); err == nil {
		t.Fatal("want an error when one product cannot be fetched")
	}
}

func TestWriteKeepsTheOldFileWhenTheNewSnapshotIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vdb.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := Snapshot{SchemaVersion: 1, GeneratedAt: time.Now().Unix(), Products: map[string][]Advisory{}}
	if _, err := Write(path, empty); err == nil {
		t.Fatal("wrote a snapshot with no products")
	}
	if b, _ := os.ReadFile(path); string(b) != "old" {
		t.Fatalf("old file replaced with %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".vdb-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}
