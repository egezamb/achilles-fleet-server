// Package snapshot builds the VDB snapshot the server hands to Achilles agents
// (docs/vdb-snapshot-schema.md in crabnebula-dev/achilles) from OSV.
//
// It covers the products Achilles itself looks up in OSV: electron (npm),
// tauri (crates.io) and react_native (npm). The agent asks no other source
// for a product the snapshot covers, and falls back to the public feeds for
// the rest.
package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/egezamb/achilles-fleet-server/internal/osv"
	"github.com/egezamb/achilles-fleet-server/internal/vdb"
)

// Product is one product key of the snapshot and the OSV package behind it.
type Product struct {
	Key, Ecosystem, Name string
}

// Products are the products Achilles queries OSV for (crates/cve/src/lib.rs).
var Products = []Product{
	{Key: "electron", Ecosystem: "npm", Name: "electron"},
	{Key: "tauri", Ecosystem: "crates.io", Name: "tauri"},
	{Key: "react_native", Ecosystem: "npm", Name: "react-native"},
}

// Advisory is the agent's cve::advisory::Advisory. aliases and references
// are never null: the agent's matcher drops the whole snapshot if one is.
type Advisory struct {
	ID         string   `json:"id"`
	Source     string   `json:"source"`
	Summary    string   `json:"summary"`
	Severity   *string  `json:"severity"`
	FixedIn    *string  `json:"fixed_in"`
	Aliases    []string `json:"aliases"`
	Published  *string  `json:"published"`
	References []string `json:"references"`
}

// Snapshot is the file the server serves at /v1/vdb.
type Snapshot struct {
	SchemaVersion  int                   `json:"schema_version"`
	GeneratedAt    int64                 `json:"generated_at"`
	GeneratedAtISO string                `json:"generated_at_iso"`
	Products       map[string][]Advisory `json:"products"`
}

// Fetcher returns every OSV record for a package; osv.Client.Package is one.
type Fetcher func(ctx context.Context, ecosystem, name string) ([]osv.Vuln, error)

// Build queries OSV for each product. It fails if any product fails, rather
// than leave a product out: a product missing from the snapshot sends agents
// back to the public feeds for it, which an operator should hear about.
func Build(ctx context.Context, fetch Fetcher, products []Product, now time.Time) (Snapshot, error) {
	s := Snapshot{
		SchemaVersion:  1,
		GeneratedAt:    now.Unix(),
		GeneratedAtISO: now.UTC().Format(time.RFC3339),
		Products:       map[string][]Advisory{},
	}
	for _, p := range products {
		vulns, err := fetch(ctx, p.Ecosystem, p.Name)
		if err != nil {
			return Snapshot{}, err
		}
		list := []Advisory{}
		for _, v := range vulns {
			if a, ok := Convert(v, p.Ecosystem, p.Name); ok {
				list = append(list, a)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		s.Products[p.Key] = list
	}
	return s, nil
}

// Convert turns an OSV record into the agent's advisory for one package, the
// way Achilles' own OSV source does (crates/cve/src/sources/osv.rs), except
// for fixed_in. It reports false for a withdrawn record or one that does not
// affect the package.
//
// fixed_in: the agent keeps an advisory for version V when V < fixed_in, and
// the snapshot has no field for where a range starts. A record fixed on
// several release lines (Electron backports most fixes) cannot be told apart
// per line, so fixed_in is the highest fix: every affected version is still
// reported, at the cost of also reporting older lines that got the fix. When
// a range has no fix, or a fix cannot be compared, fixed_in is null and the
// advisory applies to every version.
func Convert(v osv.Vuln, ecosystem, name string) (Advisory, bool) {
	if v.Withdrawn != "" {
		return Advisory{}, false
	}
	var ranges []osv.Range
	for _, a := range v.Affected {
		if a.Package.Ecosystem == ecosystem && a.Package.Name == name {
			ranges = append(ranges, a.Ranges...)
		}
	}
	if len(ranges) == 0 {
		return Advisory{}, false
	}
	a := Advisory{
		ID:         v.ID,
		Source:     "osv",
		Summary:    v.Summary,
		Severity:   severity(v.DatabaseSpecific.Severity),
		FixedIn:    highestFix(ranges),
		Aliases:    append([]string{}, v.Aliases...),
		References: []string{},
	}
	if v.Published != "" {
		a.Published = &v.Published
	}
	for _, r := range v.References {
		if r.URL != "" {
			a.References = append(a.References, r.URL)
		}
	}
	return a, true
}

// severity maps OSV's database_specific.severity as the agent's
// Severity::from_str does. Anything else is null, which the agent accepts;
// "moderate" itself would make it drop the snapshot.
func severity(s string) *string {
	var v string
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		v = "low"
	case "MODERATE", "MEDIUM":
		v = "medium"
	case "HIGH":
		v = "high"
	case "CRITICAL":
		v = "critical"
	default:
		return nil
	}
	return &v
}

func highestFix(ranges []osv.Range) *string {
	best := ""
	for _, r := range ranges {
		if r.Type == "GIT" {
			continue // commit hashes, not versions; the record's SEMVER range says the same
		}
		open := false
		for _, e := range r.Events {
			if _, ok := e["introduced"]; ok {
				open = true
			}
			fixed, ok := e["fixed"]
			if !ok {
				continue
			}
			if !semver.IsValid("v" + fixed) {
				return nil
			}
			if best == "" || semver.Compare("v"+fixed, "v"+best) > 0 {
				best = fixed
			}
			open = false
		}
		// introduced with no fix after it (or only last_affected): no version
		// of this line is known to be safe.
		if open {
			return nil
		}
	}
	if best == "" {
		return nil
	}
	return &best
}

// Write checks the snapshot the way the server will (vdb.Validate) and then
// replaces path atomically, so the server never reads a half-written file and
// a snapshot it would refuse is never written over a good one.
func Write(path string, s Snapshot) (vdb.Info, error) {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return vdb.Info{}, err
	}
	info, err := vdb.Validate(b)
	if err != nil {
		return vdb.Info{}, fmt.Errorf("refusing to write a snapshot the agent would ignore: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vdb-*.json")
	if err != nil {
		return vdb.Info{}, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return vdb.Info{}, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return vdb.Info{}, err
	}
	if err := tmp.Close(); err != nil {
		return vdb.Info{}, err
	}
	return info, os.Rename(tmp.Name(), path)
}
