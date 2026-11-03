package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egezamb/achilles-fleet-server/internal/store"
	"github.com/egezamb/achilles-fleet-server/internal/vdb"
)

const (
	reportToken = "report-secret"
	readToken   = "read-secret"
)

// docReport is the request body example from docs/collector-schema.md.
func docReport(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/report-doc-example.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newServer(t *testing.T, cfg Config, snapshot *vdb.File) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if cfg.ReportToken == "" {
		cfg.ReportToken = reportToken
	}
	return New(cfg, st, snapshot).Handler()
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func devices(t *testing.T, h http.Handler, query string) []store.Device {
	t.Helper()
	rec := do(t, h, "GET", "/v1/devices"+query, readToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/devices: %d %s", rec.Code, rec.Body)
	}
	var out struct{ Devices []store.Device }
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Devices
}

func TestDocExampleReportIsStored(t *testing.T) {
	h := newServer(t, Config{ReadToken: readToken}, nil)

	rec := do(t, h, "POST", "/v1/reports", reportToken, docReport(t))
	if rec.Code/100 != 2 {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body)
	}

	got := devices(t, h, "")
	if len(got) != 1 {
		t.Fatalf("want 1 device, got %d", len(got))
	}
	d := got[0]
	if d.ID != "f1e2d3c4-5678-49ab-cdef-0123456789ab" || d.FleetID != "acme-corp" || d.OS != "macos" {
		t.Errorf("device fields: %+v", d)
	}
	if len(d.Apps) != 1 || d.Apps[0].Runtimes["chromium"] != "138.0.7204.251" || *d.Apps[0].Name != "Discord" {
		t.Errorf("apps: %+v", d.Apps)
	}
}

func TestReportNeedsTheToken(t *testing.T) {
	h := newServer(t, Config{}, nil)
	for name, token := range map[string]string{"none": "", "wrong": "nope"} {
		if rec := do(t, h, "POST", "/v1/reports", token, docReport(t)); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s token: want 401, got %d", name, rec.Code)
		}
	}
}

func TestRejectsWhatTheAgentNeverSends(t *testing.T) {
	h := newServer(t, Config{}, nil)
	cases := map[string]string{
		"schema 2":     strings.Replace(docReport(t), `"schema_version": 1`, `"schema_version": 2`, 1),
		"no device id": strings.Replace(docReport(t), `"f1e2d3c4-5678-49ab-cdef-0123456789ab"`, `""`, 1),
		"unknown fw":   strings.Replace(docReport(t), `"electron",`, `"unknown",`, 1),
		"not json":     "{",
		"two bodies":   docReport(t) + docReport(t),
	}
	for name, body := range cases {
		rec := do(t, h, "POST", "/v1/reports", reportToken, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", name, rec.Code, rec.Body)
		}
		// The agent shows the first 200 characters of the body to the user.
		if rec.Body.Len() == 0 || rec.Body.Len() > 200 {
			t.Errorf("%s: error body should be a short reason, got %d bytes", name, rec.Body.Len())
		}
	}
}

// The agent sends "deno" and nulls for name/bundle fields; both must round-trip.
func TestNullFieldsAndNewRuntimesRoundTrip(t *testing.T) {
	h := newServer(t, Config{ReadToken: readToken}, nil)
	body := strings.Replace(docReport(t), `"apps": [`, `"apps": [
		{"name": null, "bundle_id": null, "bundle_version": null, "framework": "deno", "runtimes": {"deno": "2.7.5"}},`, 1)
	if rec := do(t, h, "POST", "/v1/reports", reportToken, body); rec.Code/100 != 2 {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body)
	}
	apps := devices(t, h, "")[0].Apps
	if len(apps) != 2 || apps[0].Name != nil || apps[0].Framework != "deno" || apps[0].Runtimes["deno"] != "2.7.5" {
		t.Fatalf("apps: %+v", apps)
	}
}

func TestNewerReportReplacesAndOlderIsDropped(t *testing.T) {
	h := newServer(t, Config{ReadToken: readToken}, nil)
	base := docReport(t)
	newer := strings.Replace(strings.Replace(base, "1750598400", "1750602000", 1), `"Discord"`, `"Slack"`, 1)

	for _, body := range []string{base, newer} {
		if rec := do(t, h, "POST", "/v1/reports", reportToken, body); rec.Code != http.StatusNoContent {
			t.Fatalf("POST: %d %s", rec.Code, rec.Body)
		}
	}
	// A retry of the first report arrives late. It must succeed for the agent
	// (any non-2xx makes it retry forever) but not overwrite the newer data.
	if rec := do(t, h, "POST", "/v1/reports", reportToken, base); rec.Code != http.StatusAccepted {
		t.Fatalf("late report: want 202, got %d", rec.Code)
	}
	d := devices(t, h, "")[0]
	if d.GeneratedAt != 1750602000 || len(d.Apps) != 1 || *d.Apps[0].Name != "Slack" {
		t.Fatalf("want only the newer inventory, got %+v", d)
	}
}

func TestDevicesFilterByFleet(t *testing.T) {
	h := newServer(t, Config{ReadToken: readToken}, nil)
	other := strings.Replace(strings.Replace(docReport(t), "acme-corp", "other", 1), "f1e2d3c4", "a0a0a0a0", 1)
	for _, body := range []string{docReport(t), other} {
		do(t, h, "POST", "/v1/reports", reportToken, body)
	}
	if n := len(devices(t, h, "")); n != 2 {
		t.Errorf("all fleets: want 2, got %d", n)
	}
	got := devices(t, h, "?fleet_id=other")
	if len(got) != 1 || got[0].FleetID != "other" || len(got[0].Apps) != 1 {
		t.Errorf("fleet filter: %+v", got)
	}
}

func TestReadAPI(t *testing.T) {
	if rec := do(t, newServer(t, Config{}, nil), "GET", "/v1/devices", readToken, ""); rec.Code != http.StatusNotFound {
		t.Errorf("no read token configured: want 404, got %d", rec.Code)
	}
	h := newServer(t, Config{ReadToken: readToken}, nil)
	if rec := do(t, h, "GET", "/v1/devices", reportToken, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("report token on the read API: want 401, got %d", rec.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	h := newServer(t, Config{MaxBody: 100}, nil)
	if rec := do(t, h, "POST", "/v1/reports", reportToken, docReport(t)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", rec.Code)
	}
}

func writeSnapshot(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "vdb.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func docSnapshot(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/vdb-doc-example.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestVDBServesTheDocExample(t *testing.T) {
	p := writeSnapshot(t, t.TempDir(), docSnapshot(t))
	h := newServer(t, Config{}, vdb.NewFile(p, 0))

	rec := do(t, h, "GET", "/v1/vdb", reportToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/vdb: %d %s", rec.Code, rec.Body)
	}
	if b, _ := io.ReadAll(rec.Body); string(b) != docSnapshot(t) {
		t.Error("served bytes differ from the file")
	}
}

// Same fallback as the agent: with no VDB token, the report token works.
func TestVDBTokens(t *testing.T) {
	p := writeSnapshot(t, t.TempDir(), docSnapshot(t))
	h := newServer(t, Config{VDBToken: "vdb-secret"}, vdb.NewFile(p, 0))
	if rec := do(t, h, "GET", "/v1/vdb", "vdb-secret", ""); rec.Code != http.StatusOK {
		t.Errorf("vdb token: want 200, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/vdb", reportToken, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("report token when a vdb token is set: want 401, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/vdb", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: want 401, got %d", rec.Code)
	}
}

func TestVDBWithholdsWhatTheAgentWouldIgnore(t *testing.T) {
	noAliases := strings.Replace(docSnapshot(t), `"aliases": ["GHSA-xxxx-yyyy-zzzz"],`, "", 1)
	p := writeSnapshot(t, t.TempDir(), noAliases)
	h := newServer(t, Config{}, vdb.NewFile(p, 0))
	rec := do(t, h, "GET", "/v1/vdb", reportToken, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestVDBWithholdsAStaleSnapshot(t *testing.T) {
	p := writeSnapshot(t, t.TempDir(), docSnapshot(t)) // generated 2025-06-22
	h := newServer(t, Config{}, vdb.NewFile(p, 14*24*time.Hour))
	if rec := do(t, h, "GET", "/v1/vdb", reportToken, ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 for a snapshot past max age, got %d", rec.Code)
	}
}

func TestVDBKeepsTheLastGoodCopy(t *testing.T) {
	dir := t.TempDir()
	p := writeSnapshot(t, dir, docSnapshot(t))
	h := newServer(t, Config{}, vdb.NewFile(p, 0))
	if rec := do(t, h, "GET", "/v1/vdb", reportToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("first load: %d", rec.Code)
	}
	// A broken rewrite (different size, so it is noticed) must not take the
	// snapshot away from the fleet.
	writeSnapshot(t, dir, `{"products": {}}`)
	rec := do(t, h, "GET", "/v1/vdb", reportToken, "")
	if rec.Code != http.StatusOK || rec.Body.String() != docSnapshot(t) {
		t.Fatalf("want the last good snapshot, got %d", rec.Code)
	}
}

func TestVDBOffWithoutAFile(t *testing.T) {
	if rec := do(t, newServer(t, Config{}, nil), "GET", "/v1/vdb", reportToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestRejectsAReportFromTheFuture(t *testing.T) {
	h := newServer(t, Config{}, nil)
	future := strings.Replace(docReport(t), "1750598400", "4102444800", 1) // 2100-01-01
	if rec := do(t, h, "POST", "/v1/reports", reportToken, future); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// An oversized field is cut, not rejected: a rejected report would be resent
// unchanged every run and the device would never show up.
func TestOversizedFieldsAreClipped(t *testing.T) {
	h := newServer(t, Config{ReadToken: readToken}, nil)
	long := strings.Repeat("é", 400) // 800 bytes
	body := strings.Replace(docReport(t), `"Janes-MacBook-Pro"`, `"`+long+`"`, 1)
	if rec := do(t, h, "POST", "/v1/reports", reportToken, body); rec.Code != http.StatusNoContent {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body)
	}
	got := devices(t, h, "")[0].Hostname
	if len(got) > 512 || !strings.HasPrefix(long, got) || got == "" {
		t.Fatalf("hostname not clipped on a character boundary: %d bytes", len(got))
	}
}

// Reports from many devices at once must all land: SQLite has one writer, and
// a deferred transaction that upgrades to a write lock can fail with BUSY.
func TestConcurrentReports(t *testing.T) {
	h := newServer(t, Config{ReadToken: readToken}, nil)
	const n = 40
	errs := make(chan string, n)
	for i := range n {
		go func() {
			body := strings.Replace(docReport(t), "f1e2d3c4-5678", fmt.Sprintf("%08x-5678", i), 1)
			rec := do(t, h, "POST", "/v1/reports", reportToken, body)
			if rec.Code != http.StatusNoContent {
				errs <- fmt.Sprintf("device %d: %d %s", i, rec.Code, rec.Body)
				return
			}
			errs <- ""
		}()
	}
	for range n {
		if e := <-errs; e != "" {
			t.Error(e)
		}
	}
	if got := len(devices(t, h, "")); got != n {
		t.Fatalf("want %d devices, got %d", n, got)
	}
}
