// Package osv reads every advisory OSV holds for one package
// (https://google.github.io/osv.dev/post-v1-query/).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultURL is OSV's query endpoint.
const DefaultURL = "https://api.osv.dev/v1/query"

// Vuln is the part of an OSV record a snapshot needs.
type Vuln struct {
	ID               string      `json:"id"`
	Summary          string      `json:"summary"`
	Aliases          []string    `json:"aliases"`
	Published        string      `json:"published"`
	Withdrawn        string      `json:"withdrawn"`
	References       []Reference `json:"references"`
	Affected         []Affected  `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type Reference struct {
	URL string `json:"url"`
}

type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []Range `json:"ranges"`
}

type Range struct {
	Type string `json:"type"`
	// Each event has one key: introduced, fixed, last_affected or limit.
	Events []map[string]string `json:"events"`
}

// Client queries OSV. The zero value uses DefaultURL and a 30 second timeout.
type Client struct {
	URL  string
	HTTP *http.Client
}

// maxPages bounds the paging, so a server that always returns a page token
// cannot keep a build running forever.
const maxPages = 100

// Package returns every advisory OSV has for a package, following
// next_page_token until the last page.
func (c Client) Package(ctx context.Context, ecosystem, name string) ([]Vuln, error) {
	url := c.URL
	if url == "" {
		url = DefaultURL
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	var all []Vuln
	token := ""
	for page := 0; ; page++ {
		if page == maxPages {
			return nil, fmt.Errorf("osv %s/%s: more than %d pages", ecosystem, name, maxPages)
		}
		q := map[string]any{"package": map[string]string{"ecosystem": ecosystem, "name": name}}
		if token != "" {
			q["page_token"] = token
		}
		body, _ := json.Marshal(q)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("osv %s/%s: %w", ecosystem, name, err)
		}
		var out struct {
			Vulns         []Vuln `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		}
		err = decode(resp, &out)
		if err != nil {
			return nil, fmt.Errorf("osv %s/%s: %w", ecosystem, name, err)
		}
		all = append(all, out.Vulns...)
		if out.NextPageToken == "" {
			return all, nil
		}
		token = out.NextPageToken
	}
}

func decode(resp *http.Response, dst any) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
