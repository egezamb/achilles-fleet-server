// Package vdb serves a trusted-host vulnerability snapshot to Achilles agents
// (docs/vdb-snapshot-schema.md in crabnebula-dev/achilles).
//
// The agent caches whatever parses with a non-empty "products" map, but its
// matcher (crates/cve/src/sources/snapshot.rs) needs every advisory to carry
// id, source, summary, aliases and references, with a known source and
// severity. If one advisory is off, the matcher drops the whole snapshot and
// silently falls back to the public feeds. So a snapshot is checked against
// the matcher's rules here, and one that fails is never served.
package vdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"
)

var (
	sources    = map[string]bool{"osv": true, "nvd": true, "euvd": true, "ghsa": true}
	severities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
)

// Info describes the snapshot being served.
type Info struct {
	GeneratedAt time.Time
	Products    int
	Advisories  int
}

// Validate checks a snapshot the way the agent's matcher will read it.
func Validate(b []byte) (Info, error) {
	top, err := object(b, "schema_version", "generated_at", "products")
	if err != nil {
		return Info{}, fmt.Errorf("not a snapshot: %w", err)
	}
	if v, ok := top["schema_version"]; ok {
		var n uint32
		if err := strict(v, &n); err != nil {
			return Info{}, fmt.Errorf("schema_version: %w", err)
		}
		if n != 1 {
			return Info{}, fmt.Errorf("schema_version %d is not supported (want 1)", n)
		}
	}
	var generated uint64
	if v, ok := top["generated_at"]; !ok || strict(v, &generated) != nil || generated == 0 {
		// The agent defaults a missing value to 0, which makes the cached copy
		// count as stale at once and get deleted on the first failed refresh.
		return Info{}, errors.New("generated_at is missing or not a positive unix time")
	}
	var products map[string]json.RawMessage
	if v, ok := top["products"]; ok {
		if err := strict(v, &products); err != nil {
			return Info{}, fmt.Errorf("products: %w", err)
		}
	}
	if len(products) == 0 {
		return Info{}, errors.New("products is empty; the agent rejects such a snapshot")
	}
	info := Info{GeneratedAt: time.Unix(int64(generated), 0).UTC(), Products: len(products)}
	for product, raw := range products {
		var list []json.RawMessage
		if err := strict(raw, &list); err != nil {
			return Info{}, fmt.Errorf("products.%s: want a list: %w", product, err)
		}
		for i, adv := range list {
			if err := validateAdvisory(adv); err != nil {
				return Info{}, fmt.Errorf("products.%s[%d]: %w", product, i, err)
			}
		}
		info.Advisories += len(list)
	}
	return info, nil
}

func validateAdvisory(raw json.RawMessage) error {
	f, err := object(raw, "id", "source", "summary", "severity", "fixed_in", "aliases", "published", "references")
	if err != nil {
		return err
	}
	var s string
	for _, k := range []string{"id", "source", "summary"} {
		v, ok := f[k]
		if !ok {
			return fmt.Errorf("missing %s", k)
		}
		if err := strict(v, &s); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		if k == "source" && !sources[s] {
			return fmt.Errorf("source %q is not one of osv, nvd, euvd, ghsa", s)
		}
	}
	for _, k := range []string{"aliases", "references"} {
		v, ok := f[k]
		if !ok {
			return fmt.Errorf("missing %s (use [] when there are none)", k)
		}
		var l []json.RawMessage
		if err := strict(v, &l); err != nil {
			return fmt.Errorf("%s: want a list of strings: %w", k, err)
		}
		for _, e := range l {
			if err := strict(e, &s); err != nil {
				return fmt.Errorf("%s: want a list of strings: %w", k, err)
			}
		}
	}
	for _, k := range []string{"severity", "fixed_in", "published"} {
		v, ok := f[k]
		if !ok || string(v) == "null" {
			continue // Option<T>: absent and null both mean None
		}
		if err := strict(v, &s); err != nil {
			return fmt.Errorf("%s: want a string or null: %w", k, err)
		}
		if k == "severity" && !severities[s] {
			return fmt.Errorf("severity %q is not one of low, medium, high, critical", s)
		}
	}
	return nil
}

// strict decodes v into dst but, unlike encoding/json, refuses null: serde
// accepts null only for Option fields, which the callers handle themselves.
func strict(v json.RawMessage, dst any) error {
	if string(bytes.TrimSpace(v)) == "null" {
		return errors.New("is null")
	}
	return json.Unmarshal(v, dst)
}

// object reads a JSON object into its raw fields, matching keys exactly as
// serde does (encoding/json would also match "Products" to products). A
// repeated known field is an error in serde, so it is one here; repeated
// unknown fields are ignored by both.
func object(b []byte, known ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup && slices.Contains(known, key) {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return out, nil
}

// File serves the snapshot at a path, reloading it when the file changes. A
// changed file that fails validation is logged and the last good copy keeps
// being served.
type File struct {
	path   string
	maxAge time.Duration
	now    func() time.Time

	mu      sync.Mutex
	modTime time.Time
	size    int64
	body    []byte
	info    Info
}

func NewFile(path string, maxAge time.Duration) *File {
	return &File{path: path, maxAge: maxAge, now: time.Now}
}

// ErrUnavailable means there is no valid, fresh snapshot to serve.
var ErrUnavailable = errors.New("no valid snapshot")

// Current returns the snapshot to serve. A snapshot older than maxAge is
// withheld: the agent only checks freshness when a download fails, so serving
// an old file with a 2xx would keep devices on it indefinitely, while an error
// lets their own max-age rule drop it.
func (f *File) Current() ([]byte, Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reload()
	if f.body == nil {
		return nil, Info{}, ErrUnavailable
	}
	if f.maxAge > 0 && f.now().Sub(f.info.GeneratedAt) > f.maxAge {
		return nil, f.info, fmt.Errorf("%w: generated %s, older than %s", ErrUnavailable, f.info.GeneratedAt.Format(time.RFC3339), f.maxAge)
	}
	return f.body, f.info, nil
}

func (f *File) reload() {
	st, err := os.Stat(f.path)
	if err != nil {
		if f.body != nil {
			slog.Warn("vdb snapshot unreadable, serving the last good copy", "path", f.path, "err", err)
		}
		return
	}
	if st.ModTime().Equal(f.modTime) && st.Size() == f.size {
		return
	}
	b, err := os.ReadFile(f.path)
	if err != nil {
		// Leave modTime alone so the next request tries again.
		slog.Error("read vdb snapshot", "path", f.path, "err", err)
		return
	}
	f.modTime, f.size = st.ModTime(), st.Size()
	info, err := Validate(b)
	if err != nil {
		slog.Error("vdb snapshot rejected, the agent would ignore it", "path", f.path, "err", err)
		return
	}
	f.body, f.info = b, info
	slog.Info("vdb snapshot loaded", "path", f.path, "generated_at", info.GeneratedAt, "products", info.Products, "advisories", info.Advisories)
}
