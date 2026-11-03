// Package server is the HTTP side of the collector: agents POST reports and
// GET the VDB snapshot; operators read the inventory back.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/egezamb/achilles-fleet-server/internal/report"
	"github.com/egezamb/achilles-fleet-server/internal/store"
	"github.com/egezamb/achilles-fleet-server/internal/vdb"
)

// Config holds the tokens and limits. An empty ReportToken is refused at
// startup (see cmd); the others are optional.
type Config struct {
	// ReportToken is what agents send as "token" in their fleet settings.
	ReportToken string
	// VDBToken guards the snapshot. When empty, ReportToken is accepted, the
	// same fallback the agent uses when its vdb_token is empty.
	VDBToken string
	// ReadToken guards GET /v1/devices. When empty, that endpoint is off.
	ReadToken string
	// MaxBody caps a report's size in bytes.
	MaxBody int64
}

type Server struct {
	cfg   Config
	store *store.Store
	vdb   *vdb.File // nil when no snapshot is configured
	now   func() time.Time
}

func New(cfg Config, st *store.Store, snapshot *vdb.File) *Server {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 8 << 20
	}
	return &Server{cfg: cfg, store: st, vdb: snapshot, now: time.Now}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/reports", s.postReport)
	mux.HandleFunc("GET /v1/vdb", s.getVDB)
	mux.HandleFunc("GET /v1/devices", s.getDevices)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /readyz", s.ready)
	return mux
}

// bearer reports whether the request carries one of the tokens. Empty tokens
// never match.
func bearer(r *http.Request, tokens ...string) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || got == "" {
		return false
	}
	for _, t := range tokens {
		if t != "" && subtle.ConstantTimeCompare([]byte(got), []byte(t)) == 1 {
			return true
		}
	}
	return false
}

// fail answers with a short plain-text reason. The agent shows the first 200
// characters of a non-2xx body to the user, so the reason should fit in that.
func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

func (s *Server) postReport(w http.ResponseWriter, r *http.Request) {
	if !bearer(r, s.cfg.ReportToken) {
		fail(w, http.StatusUnauthorized, "missing or wrong bearer token")
		return
	}
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBody)
	rep, err := report.Decode(body, s.now())
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("report is larger than %d bytes", s.cfg.MaxBody))
			return
		}
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	outcome, err := s.store.Save(r.Context(), rep, s.now())
	if err != nil {
		slog.Error("save report", "device", rep.Device.ID, "err", err)
		fail(w, http.StatusInternalServerError, "could not store the report")
		return
	}
	if outcome == store.Stale {
		// Still 2xx: the agent treats anything else as a failure and would
		// keep resending a report that can never win.
		slog.Info("dropped an older report", "device", rep.Device.ID, "generated_at", rep.GeneratedAt)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	slog.Info("report stored", "device", rep.Device.ID, "fleet", rep.FleetID, "apps", len(rep.Apps))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getVDB(w http.ResponseWriter, r *http.Request) {
	if s.vdb == nil {
		fail(w, http.StatusNotFound, "this collector serves no VDB snapshot")
		return
	}
	if !bearer(r, s.cfg.VDBToken, s.vdbFallback()) {
		fail(w, http.StatusUnauthorized, "missing or wrong bearer token")
		return
	}
	body, info, err := s.vdb.Current()
	if err != nil {
		fail(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Last-Modified", info.GeneratedAt.Format(http.TimeFormat))
	w.Write(body)
}

func (s *Server) vdbFallback() string {
	if s.cfg.VDBToken == "" {
		return s.cfg.ReportToken
	}
	return ""
}

func (s *Server) getDevices(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ReadToken == "" {
		fail(w, http.StatusNotFound, "the read API is off; set a read token to enable it")
		return
	}
	if !bearer(r, s.cfg.ReadToken) {
		fail(w, http.StatusUnauthorized, "missing or wrong bearer token")
		return
	}
	devices, err := s.store.Devices(r.Context(), r.URL.Query().Get("fleet_id"))
	if err != nil {
		slog.Error("list devices", "err", err)
		fail(w, http.StatusInternalServerError, "could not read the inventory")
		return
	}
	if devices == nil {
		devices = []store.Device{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"devices": devices})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		fail(w, http.StatusServiceUnavailable, "database: "+err.Error())
		return
	}
	fmt.Fprintln(w, "ok")
}
