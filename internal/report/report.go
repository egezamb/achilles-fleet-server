// Package report decodes and validates the inventory an Achilles fleet agent
// POSTs to its collector (docs/collector-schema.md in crabnebula-dev/achilles,
// schema_version 1).
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// SchemaVersion is the only report version this collector accepts.
const SchemaVersion = 1

// Limits keep one device from filling the database. A real machine reports
// tens to a few hundred apps; the ceilings are far above that.
const (
	maxApps      = 5000
	maxRuntimes  = 32
	maxFieldLen  = 512
	maxDeviceLen = 128
)

type Report struct {
	SchemaVersion  int    `json:"schema_version"`
	GeneratedAt    int64  `json:"generated_at"`
	GeneratedAtISO string `json:"generated_at_iso"`
	FleetID        string `json:"fleet_id"`
	Device         Device `json:"device"`
	Apps           []App  `json:"apps"`
}

type Device struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	AppVersion string `json:"app_version"`
}

// App is one installed application. Name, BundleID and BundleVersion may be
// null on the wire.
type App struct {
	Name          *string           `json:"name"`
	BundleID      *string           `json:"bundle_id"`
	BundleVersion *string           `json:"bundle_version"`
	Framework     string            `json:"framework"`
	Runtimes      map[string]string `json:"runtimes"`
}

// Decode reads one report and validates it against now. Unknown fields are
// ignored so a newer agent that adds fields still reports; a different
// schema_version is rejected because its meaning may have changed.
func Decode(r io.Reader, now time.Time) (*Report, error) {
	var rep Report
	dec := json.NewDecoder(r)
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("body is not a JSON report: %w", err)
	}
	if dec.More() {
		return nil, errors.New("body has data after the report")
	}
	if err := rep.Validate(now); err != nil {
		return nil, err
	}
	return &rep, nil
}

// maxClockSkew is how far in the future generated_at may be. A report dated
// later would block every real report from that device until the clock caught
// up, because only a newer report replaces a stored one.
const maxClockSkew = 24 * time.Hour

// Validate rejects what no agent sends and shortens over-long strings. An
// oversized field is cut rather than rejected: the agent would resend the same
// report every run and the device would never report at all.
func (r *Report) Validate(now time.Time) error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version %d is not supported (want %d)", r.SchemaVersion, SchemaVersion)
	}
	if r.GeneratedAt <= 0 {
		return errors.New("generated_at must be a positive unix time")
	}
	if limit := now.Add(maxClockSkew).Unix(); r.GeneratedAt > limit {
		return fmt.Errorf("generated_at %d is more than %s in the future; check the device clock", r.GeneratedAt, maxClockSkew)
	}
	id := strings.TrimSpace(r.Device.ID)
	if id == "" {
		return errors.New("device.id is empty")
	}
	if len(id) > maxDeviceLen {
		return fmt.Errorf("device.id is longer than %d bytes", maxDeviceLen)
	}
	if len(r.Apps) > maxApps {
		return fmt.Errorf("%d apps is more than the limit of %d", len(r.Apps), maxApps)
	}
	for _, p := range []*string{&r.FleetID, &r.Device.Hostname, &r.Device.OS, &r.Device.Arch, &r.Device.AppVersion} {
		*p = clip(*p)
	}
	for i := range r.Apps {
		a := &r.Apps[i]
		if a.Framework == "" {
			return fmt.Errorf("apps[%d].framework is empty", i)
		}
		if a.Framework == "unknown" {
			// The agent filters these out; seeing one means a broken or foreign client.
			return fmt.Errorf("apps[%d].framework is \"unknown\", which agents never send", i)
		}
		if len(a.Runtimes) > maxRuntimes {
			return fmt.Errorf("apps[%d] has more than %d runtimes", i, maxRuntimes)
		}
		a.Framework = clip(a.Framework)
		for _, p := range []*string{a.Name, a.BundleID, a.BundleVersion} {
			if p != nil {
				*p = clip(*p)
			}
		}
		for k, v := range a.Runtimes {
			if k == "" || len(k) > maxFieldLen {
				delete(a.Runtimes, k)
				continue
			}
			a.Runtimes[k] = clip(v)
		}
	}
	return nil
}

// clip shortens s to maxFieldLen bytes without splitting a UTF-8 character.
func clip(s string) string {
	if len(s) <= maxFieldLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxFieldLen], "")
}
