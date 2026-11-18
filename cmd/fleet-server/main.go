// Command fleet-server is a collector and VDB host for Achilles fleet agents.
//
// Configuration comes from the environment, so the same binary runs the same
// way under Docker, Kubernetes and a shell:
//
//	FLEET_LISTEN        address to listen on (default :8080)
//	FLEET_DB            SQLite database path (default fleet.db)
//	FLEET_REPORT_TOKEN  bearer token agents report with (required)
//	FLEET_VDB_TOKEN     bearer token for the snapshot (default: the report token)
//	FLEET_READ_TOKEN    bearer token for GET /v1/devices (unset: endpoint off)
//	FLEET_VDB_FILE      snapshot to serve at GET /v1/vdb (unset: endpoint off)
//	FLEET_VDB_MAX_AGE   withhold a snapshot older than this (default 336h, the agent's own default)
//	FLEET_MAX_BODY      largest report accepted, in bytes (default 8388608)
//
// "fleet-server build-vdb -o FILE" builds a snapshot from OSV instead of
// serving, checks it as the server would and replaces FILE only if it passes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/egezamb/achilles-fleet-server/internal/osv"
	"github.com/egezamb/achilles-fleet-server/internal/server"
	"github.com/egezamb/achilles-fleet-server/internal/snapshot"
	"github.com/egezamb/achilles-fleet-server/internal/store"
	"github.com/egezamb/achilles-fleet-server/internal/vdb"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) > 1 && os.Args[1] == "build-vdb" {
		if err := buildVDB(os.Args[2:]); err != nil {
			slog.Error("build-vdb failed", "err", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("fleet-server stopped", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func run() error {
	cfg := server.Config{
		ReportToken: os.Getenv("FLEET_REPORT_TOKEN"),
		VDBToken:    os.Getenv("FLEET_VDB_TOKEN"),
		ReadToken:   os.Getenv("FLEET_READ_TOKEN"),
	}
	if cfg.ReportToken == "" {
		return errors.New("FLEET_REPORT_TOKEN is not set; refusing to accept reports from anyone")
	}
	maxBody, err := strconv.ParseInt(env("FLEET_MAX_BODY", "8388608"), 10, 64)
	if err != nil || maxBody <= 0 {
		return fmt.Errorf("FLEET_MAX_BODY: want a positive number of bytes, got %q", os.Getenv("FLEET_MAX_BODY"))
	}
	cfg.MaxBody = maxBody
	maxAge, err := time.ParseDuration(env("FLEET_VDB_MAX_AGE", "336h"))
	if err != nil {
		return fmt.Errorf("FLEET_VDB_MAX_AGE: %w", err)
	}

	st, err := store.Open(env("FLEET_DB", "fleet.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	var snapshot *vdb.File
	if path := os.Getenv("FLEET_VDB_FILE"); path != "" {
		snapshot = vdb.NewFile(path, maxAge)
		if _, info, err := snapshot.Current(); err != nil {
			// Not fatal: reports still work, and the file may appear later.
			slog.Warn("no servable vdb snapshot yet", "path", path, "err", err)
		} else {
			slog.Info("serving vdb snapshot", "generated_at", info.GeneratedAt, "advisories", info.Advisories)
		}
	}

	srv := &http.Server{
		Addr:              env("FLEET_LISTEN", ":8080"),
		Handler:           server.New(cfg, st, snapshot).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", srv.Addr, "vdb", snapshot != nil, "read_api", cfg.ReadToken != "")
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// buildVDB writes a snapshot built from OSV. An existing file is replaced only
// by a snapshot that passes the server's own checks.
func buildVDB(args []string) error {
	fs := flag.NewFlagSet("build-vdb", flag.ContinueOnError)
	out := fs.String("o", os.Getenv("FLEET_VDB_FILE"), "snapshot file to write (default $FLEET_VDB_FILE)")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() > 0 {
		return errors.New("usage: fleet-server build-vdb -o FILE (or set FLEET_VDB_FILE)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	s, err := snapshot.Build(ctx, osv.Client{}.Package, snapshot.Products, time.Now())
	if err != nil {
		return err
	}
	info, err := snapshot.Write(*out, s)
	if err != nil {
		return err
	}
	slog.Info("vdb snapshot written", "path", *out, "products", info.Products, "advisories", info.Advisories)
	return nil
}
