package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPackageFollowsPageTokens(t *testing.T) {
	var queries []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q map[string]any
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Errorf("bad query: %v", err)
		}
		queries = append(queries, q)
		if q["page_token"] == nil {
			w.Write([]byte(`{"vulns":[{"id":"GHSA-1"}],"next_page_token":"p2"}`))
			return
		}
		w.Write([]byte(`{"vulns":[{"id":"GHSA-2"}]}`))
	}))
	defer srv.Close()

	vulns, err := Client{URL: srv.URL}.Package(context.Background(), "npm", "electron")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 2 || vulns[0].ID != "GHSA-1" || vulns[1].ID != "GHSA-2" {
		t.Fatalf("got %+v, want GHSA-1 then GHSA-2", vulns)
	}
	if len(queries) != 2 || queries[1]["page_token"] != "p2" {
		t.Fatalf("queries %v: want a second query with page_token p2", queries)
	}
	pkg := queries[0]["package"].(map[string]any)
	if pkg["ecosystem"] != "npm" || pkg["name"] != "electron" {
		t.Fatalf("package %v, want npm/electron", pkg)
	}
}

func TestPackageReportsAnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := Client{URL: srv.URL}.Package(context.Background(), "npm", "electron")
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "npm/electron") {
		t.Fatalf("err = %v, want the status and the package", err)
	}
}

func TestPackageStopsAtAServerThatNeverEndsThePaging(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[],"next_page_token":"again"}`))
	}))
	defer srv.Close()

	if _, err := (Client{URL: srv.URL}).Package(context.Background(), "npm", "electron"); err == nil {
		t.Fatal("want an error after maxPages pages")
	}
}
