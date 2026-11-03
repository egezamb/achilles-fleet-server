package vdb

import (
	"strings"
	"testing"
)

const good = `{"schema_version":1,"generated_at":1750598400,"products":{"chromium":[
 {"id":"CVE-2026-1234","source":"nvd","summary":"x","severity":"high","fixed_in":"139.0.7258.0",
  "aliases":[],"published":null,"references":[]}]}}`

// Each case breaks one rule of the agent's matcher (serde derive on
// cve::advisory::Advisory and cve::sources::snapshot::Snapshot). The first two
// were confirmed against the agent: its downloader caches them, its matcher
// then fails to parse them and uses no snapshot at all.
func TestValidateMatchesTheAgentsMatcher(t *testing.T) {
	cases := map[string]struct{ from, to string }{
		"missing aliases":   {`"aliases":[],`, ``},
		"moderate severity": {`"high"`, `"moderate"`},
		"missing refs":      {`,"references":[]`, ``},
		"null aliases":      {`"aliases":[]`, `"aliases":null`},
		"number alias":      {`"aliases":[]`, `"aliases":[1]`},
		"null id":           {`"id":"CVE-2026-1234"`, `"id":null`},
		"missing summary":   {`"summary":"x",`, ``},
		"unknown source":    {`"nvd"`, `"mitre"`},
		"numeric fixed_in":  {`"139.0.7258.0"`, `139`},
		"null product list": {`[` + "\n" + ` {`, `null, "x":[{`},
		"empty products":    {`"products":{`, `"products":{},"ignored":{`},
		"schema 2":          {`"schema_version":1`, `"schema_version":2`},
		"no generated_at":   {`"generated_at":1750598400,`, ``},
		// Checked against serde_json in the agent's cve crate (Rust 1.99.1):
		"null schema":        {`"schema_version":1`, `"schema_version":null`},
		"null alias element": {`"aliases":[]`, `"aliases":["a",null]`},
		"duplicate id":       {`"id":"CVE-2026-1234",`, `"id":"CVE-2026-1234","id":"CVE-2",`},
		"capital Products":   {`"products"`, `"Products"`},
		"float generated_at": {`1750598400`, `1750598400.5`},
		"null generated_at":  {`1750598400`, `null`},
		"null products":      {`"products":{"chromium":[` + "\n" + ` {"id":"CVE-2026-1234","source":"nvd","summary":"x","severity":"high","fixed_in":"139.0.7258.0",` + "\n" + `  "aliases":[],"published":null,"references":[]}]}`, `"products":null`},
	}
	if _, err := Validate([]byte(good)); err != nil {
		t.Fatalf("good snapshot rejected: %v", err)
	}
	for name, c := range cases {
		bad := strings.Replace(good, c.from, c.to, 1)
		if bad == good {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := Validate([]byte(bad)); err == nil {
			t.Errorf("%s: accepted, but the agent's matcher would drop the snapshot", name)
		}
	}
}

// Optional fields may be absent or null, as serde allows for Option<T>, and
// unknown fields are ignored, as serde does without deny_unknown_fields.
func TestValidateAcceptsWhatTheMatcherAccepts(t *testing.T) {
	ok := map[string]struct{ from, to string }{
		"no severity":    {`"severity":"high",`, ``},
		"null severity":  {`"high"`, `null`},
		"no fixed_in":    {`"fixed_in":"139.0.7258.0",`, ``},
		"no published":   {`"published":null,`, ``},
		"extra field":    {`"summary":"x",`, `"summary":"x","cvss":9.8,`},
		"no schema":      {`"schema_version":1,`, ``},
		"repeated extra": {`"summary":"x",`, `"summary":"x","cvss":1,"cvss":2,`},
	}
	for name, c := range ok {
		if _, err := Validate([]byte(strings.Replace(good, c.from, c.to, 1))); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}
