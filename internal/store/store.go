// Package store keeps the latest inventory of every device in SQLite.
//
// Only the newest report per device is kept: a report is a full inventory, so
// it replaces the previous one instead of being appended to it.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/egezamb/achilles-fleet-server/internal/report"
)

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	id           TEXT PRIMARY KEY,
	fleet_id     TEXT NOT NULL,
	hostname     TEXT NOT NULL,
	os           TEXT NOT NULL,
	arch         TEXT NOT NULL,
	app_version  TEXT NOT NULL,
	generated_at INTEGER NOT NULL,
	received_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS apps (
	device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	name           TEXT,
	bundle_id      TEXT,
	bundle_version TEXT,
	framework      TEXT NOT NULL,
	runtimes       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS apps_device ON apps(device_id);
`

type Store struct {
	db *sql.DB
}

// Open opens (or creates) the database at path. WAL mode lets the read
// endpoints run while a report is being written.
func Open(path string) (*Store, error) {
	// _txlock=immediate takes the write lock at BEGIN: a transaction that
	// starts as a read and later writes can fail with SQLITE_BUSY at once,
	// without waiting out busy_timeout.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite has one writer, but in WAL mode readers don't wait for it, so a
	// few connections keep /readyz and the read API answering during a write.
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Outcome says what Save did with a report.
type Outcome int

const (
	Stored Outcome = iota
	// Stale means the device already has a newer report; this one was dropped.
	Stale
)

// Save replaces the device's inventory with the report, unless the stored one
// was generated later (a delayed retry must not overwrite a newer inventory).
func (s *Store) Save(ctx context.Context, r *report.Report, now time.Time) (Outcome, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var prev int64
	err = tx.QueryRowContext(ctx, `SELECT generated_at FROM devices WHERE id = ?`, r.Device.ID).Scan(&prev)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return 0, err
	case prev > r.GeneratedAt:
		return Stale, nil
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devices (id, fleet_id, hostname, os, arch, app_version, generated_at, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			fleet_id = excluded.fleet_id, hostname = excluded.hostname, os = excluded.os,
			arch = excluded.arch, app_version = excluded.app_version,
			generated_at = excluded.generated_at, received_at = excluded.received_at`,
		r.Device.ID, r.FleetID, r.Device.Hostname, r.Device.OS, r.Device.Arch, r.Device.AppVersion,
		r.GeneratedAt, now.Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM apps WHERE device_id = ?`, r.Device.ID); err != nil {
		return 0, err
	}
	ins, err := tx.PrepareContext(ctx, `
		INSERT INTO apps (device_id, name, bundle_id, bundle_version, framework, runtimes)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer ins.Close()
	for _, a := range r.Apps {
		rt, err := json.Marshal(a.Runtimes)
		if err != nil {
			return 0, err
		}
		if _, err := ins.ExecContext(ctx, r.Device.ID, a.Name, a.BundleID, a.BundleVersion, a.Framework, string(rt)); err != nil {
			return 0, err
		}
	}
	return Stored, tx.Commit()
}

// Device is a device with its latest inventory, as returned by the read API.
type Device struct {
	ID          string       `json:"id"`
	FleetID     string       `json:"fleet_id"`
	Hostname    string       `json:"hostname"`
	OS          string       `json:"os"`
	Arch        string       `json:"arch"`
	AppVersion  string       `json:"app_version"`
	GeneratedAt int64        `json:"generated_at"`
	ReceivedAt  int64        `json:"received_at"`
	Apps        []report.App `json:"apps"`
}

// Devices lists every device, optionally only those in one fleet, newest
// report first.
func (s *Store) Devices(ctx context.Context, fleetID string) ([]Device, error) {
	q := `SELECT id, fleet_id, hostname, os, arch, app_version, generated_at, received_at FROM devices`
	args := []any{}
	if fleetID != "" {
		q += ` WHERE fleet_id = ?`
		args = append(args, fleetID)
	}
	q += ` ORDER BY generated_at DESC, id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var out []Device
	index := map[string]int{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.FleetID, &d.Hostname, &d.OS, &d.Arch, &d.AppVersion, &d.GeneratedAt, &d.ReceivedAt); err != nil {
			rows.Close()
			return nil, err
		}
		d.Apps = []report.App{}
		index[d.ID] = len(out)
		out = append(out, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	apps, err := s.db.QueryContext(ctx, `SELECT device_id, name, bundle_id, bundle_version, framework, runtimes FROM apps ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer apps.Close()
	for apps.Next() {
		var (
			dev, fw, rt               string
			name, bundleID, bundleVer sql.NullString
		)
		if err := apps.Scan(&dev, &name, &bundleID, &bundleVer, &fw, &rt); err != nil {
			return nil, err
		}
		i, ok := index[dev]
		if !ok {
			continue // filtered out by fleet
		}
		a := report.App{Framework: fw, Name: ptr(name), BundleID: ptr(bundleID), BundleVersion: ptr(bundleVer)}
		if err := json.Unmarshal([]byte(rt), &a.Runtimes); err != nil {
			return nil, fmt.Errorf("device %s: runtimes: %w", dev, err)
		}
		out[i].Apps = append(out[i].Apps, a)
	}
	return out, apps.Err()
}

func ptr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}
