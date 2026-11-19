// Package registry maintains the live set of scanner integrations: it loads
// manifests from disk, persists them to the scanners table, instantiates
// adapter implementations, and tracks executable availability.
//
// Only registered AND enabled scanners may be executed by the orchestrator.
package registry

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/adapters/command"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
	"github.com/mauropm/wadjet/internal/scanners/nativeprobe"
	"github.com/mauropm/wadjet/internal/scanners/nmap"
)

// Scanner status values (mirror the scanners.status CHECK constraint).
const (
	StatusAvailable = "available"
	StatusMissing   = "missing"
	StatusDisabled  = "disabled"
	StatusError     = "error"
	StatusUnknown   = "unknown"
)

// availabilityTimeout bounds a single `executable --version` probe.
const availabilityTimeout = 10 * time.Second

// versionRe extracts a version token from tool --version output.
var versionRe = regexp.MustCompile(`(?i)version\s+(v?\d[\w.\-]*)`)

// Factory builds a Scanner implementation from a manifest.
type Factory func(m *manifest.Manifest) (scanners.Scanner, error)

// builtinFactories maps manifest output.parser keys to adapter
// implementations. "none"/"" archive raw output only via the generic
// command adapter.
var builtinFactories = map[string]Factory{
	"none": func(m *manifest.Manifest) (scanners.Scanner, error) {
		return command.New(m, nil)
	},
	"": func(m *manifest.Manifest) (scanners.Scanner, error) {
		return command.New(m, nil)
	},
	nmap.ParserKey:        func(m *manifest.Manifest) (scanners.Scanner, error) { return nmap.New(m) },
	nativeprobe.ParserKey: func(m *manifest.Manifest) (scanners.Scanner, error) { return nativeprobe.New(), nil },
}

// entry is one registry-managed scanner.
type entry struct {
	manifest  *manifest.Manifest
	impl      scanners.Scanner
	enabled   bool
	status    string
	statusMsg string
	version   string
}

// Registry holds the loaded scanner integrations.
type Registry struct {
	db *database.DB

	mu      sync.RWMutex
	entries map[string]*entry
}

// New creates an empty Registry bound to db.
func New(db *database.DB) *Registry {
	return &Registry{db: db, entries: map[string]*entry{}}
}

// Load reads all manifests in dir, validates them, instantiates adapters,
// and UPSERTs them into the scanners table (manifest as JSONB, initial
// status from an executable lookup). A previously disabled scanner stays
// disabled across reloads: Load never overwrites `enabled`.
func (r *Registry) Load(ctx context.Context, dir string) error {
	mfs, err := manifest.LoadDir(dir)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	for _, m := range mfs {
		factory, ok := builtinFactories[m.Output.Parser]
		if !ok {
			return fmt.Errorf("registry: manifest %s: unknown output.parser %q", m.Name, m.Output.Parser)
		}
		impl, err := factory(m)
		if err != nil {
			return fmt.Errorf("registry: manifest %s: instantiate: %w", m.Name, err)
		}
		status, statusMsg := initialStatus(m)
		manifestJSON, err := m.JSON()
		if err != nil {
			return err
		}
		var enabled bool
		err = r.db.QueryRow(ctx, `
			INSERT INTO scanners
				(name, display_name, description, version, executable, adapter,
				 enabled, asset_types, capabilities, manifest, status, status_detail,
				 documentation, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
			ON CONFLICT (name) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				description  = EXCLUDED.description,
				executable   = EXCLUDED.executable,
				adapter      = EXCLUDED.adapter,
				asset_types  = EXCLUDED.asset_types,
				capabilities = EXCLUDED.capabilities,
				manifest     = EXCLUDED.manifest,
				status       = EXCLUDED.status,
				status_detail= EXCLUDED.status_detail,
				documentation= EXCLUDED.documentation,
				updated_at   = now()
			RETURNING enabled`,
			m.Name, m.DisplayName, m.Description, m.Version, m.Executable, m.Adapter,
			m.Enabled, m.AssetTypes, m.Capabilities, manifestJSON, status, statusMsg,
			m.Documentation,
		).Scan(&enabled)
		if err != nil {
			return fmt.Errorf("registry: upsert scanner %s: %w", m.Name, err)
		}
		e := &entry{manifest: m, impl: impl, enabled: enabled, status: status, statusMsg: statusMsg, version: m.Version}
		r.mu.Lock()
		r.entries[m.Name] = e
		r.mu.Unlock()
	}
	return nil
}

// initialStatus resolves the persisted status from an executable lookup.
func initialStatus(m *manifest.Manifest) (string, string) {
	if m.Adapter == manifest.AdapterNative {
		return StatusAvailable, "in-process native scanner"
	}
	path, err := exec.LookPath(m.Executable)
	if err != nil {
		return StatusMissing, fmt.Sprintf("executable %q not found in PATH", m.Executable)
	}
	return StatusAvailable, path
}

// Get returns an executable scanner implementation: it must be registered,
// enabled, and currently available.
func (r *Registry) Get(name string) (scanners.Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	if !ok || !e.enabled {
		return nil, false
	}
	if e.status != StatusAvailable && e.manifest.Adapter == manifest.AdapterCommand {
		return nil, false
	}
	return e.impl, true
}

// Lookup returns the implementation without enabled/availability filtering.
func (r *Registry) Lookup(name string) (scanners.Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	if !ok {
		return nil, false
	}
	return e.impl, true
}

// Manifest returns a copy of the loaded manifest for name.
func (r *Registry) Manifest(name string) (*manifest.Manifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	if !ok {
		return nil, false
	}
	return e.manifest, true
}

// Enabled reports whether name is registered and enabled.
func (r *Registry) Enabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	return ok && e.enabled
}

// List returns every persisted scanner record, newest name first.
func (r *Registry) List(ctx context.Context) ([]models.ScannerRecord, error) {
	rows, err := r.db.Query(ctx, scannerSelect+` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("registry: list scanners: %w", err)
	}
	defer rows.Close()
	var out []models.ScannerRecord
	for rows.Next() {
		rec, err := scanScannerRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// GetRecord loads one persisted scanner row by id or name.
func (r *Registry) GetRecord(ctx context.Context, idOrName string) (models.ScannerRecord, error) {
	var id any
	if parsed, err := uuid.Parse(idOrName); err == nil {
		id = parsed
	} else {
		id = idOrName
	}
	where := "id = $1"
	if _, ok := id.(uuid.UUID); !ok {
		where = "name = $1"
	}
	rows, err := r.db.Query(ctx, scannerSelect+` WHERE `+where, id)
	if err != nil {
		return models.ScannerRecord{}, fmt.Errorf("registry: get scanner: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return models.ScannerRecord{}, err
		}
		return models.ScannerRecord{}, fmt.Errorf("registry: scanner %q not found", idOrName)
	}
	return scanScannerRecord(rows)
}

// Enable enables a registered scanner (persisted to the scanners table).
func (r *Registry) Enable(ctx context.Context, name string) error {
	return r.setEnabled(ctx, name, true)
}

// Disable disables a registered scanner (persisted to the scanners table).
func (r *Registry) Disable(ctx context.Context, name string) error {
	return r.setEnabled(ctx, name, false)
}

func (r *Registry) setEnabled(ctx context.Context, name string, enabled bool) error {
	r.mu.Lock()
	e, ok := r.entries[name]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("registry: scanner %q not registered", name)
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE scanners
		SET enabled = $2,
		    status = CASE
		        WHEN NOT $2 THEN 'disabled'
		        WHEN status = 'disabled' THEN 'unknown'
		        ELSE status
		    END,
		    updated_at = now()
		WHERE name = $1`, name, enabled)
	if err != nil {
		return fmt.Errorf("registry: persist enabled for %s: %w", name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("registry: scanner %q not persisted", name)
	}
	status := e.status
	if !enabled {
		status = StatusDisabled
	} else if status == StatusDisabled || status == StatusUnknown {
		status, _ = initialStatus(e.manifest)
	}
	r.mu.Lock()
	e.enabled = enabled
	e.status = status
	r.mu.Unlock()
	return nil
}

// CheckAvailability probes `executable --version` (10s bound) and persists
// the discovered version and status. Native scanners report available.
func (r *Registry) CheckAvailability(ctx context.Context, name string) (models.ScannerRecord, error) {
	r.mu.RLock()
	e, ok := r.entries[name]
	r.mu.RUnlock()
	if !ok {
		return models.ScannerRecord{}, fmt.Errorf("registry: scanner %q not registered", name)
	}

	version, detail := "", ""
	status := StatusAvailable
	if e.manifest.Adapter == manifest.AdapterNative {
		version = "builtin"
		detail = "in-process native scanner"
	} else {
		probeCtx, cancel := context.WithTimeout(ctx, availabilityTimeout)
		out, err := runVersionProbe(probeCtx, e.manifest.Executable)
		cancel()
		if err != nil {
			status = StatusMissing
			detail = truncate(err.Error(), 512)
		} else {
			version = extractVersion(out)
			if version == "" {
				version = e.manifest.Version
			}
			detail = "version probe succeeded"
		}
	}

	r.mu.Lock()
	if e.enabled {
		e.status = status
	} else {
		e.status = StatusDisabled
	}
	e.statusMsg = detail
	if version != "" {
		e.version = version
		if setter, ok := e.impl.(interface{ SetVersion(string) }); ok {
			setter.SetVersion(version)
		}
	}
	r.mu.Unlock()

	_, err := r.db.Exec(ctx, `
		UPDATE scanners
		SET version = CASE WHEN $2 = '' THEN version ELSE $2 END,
		    status  = CASE WHEN enabled THEN $3 ELSE 'disabled' END,
		    status_detail = $4,
		    last_checked_at = now(),
		    updated_at = now()
		WHERE name = $1`,
		name, version, status, detail)
	if err != nil {
		return models.ScannerRecord{}, fmt.Errorf("registry: persist availability for %s: %w", name, err)
	}
	return r.GetRecord(ctx, name)
}

// extractVersion pulls a version token out of `--version` output.
func extractVersion(out string) string {
	if m := versionRe.FindStringSubmatch(out); len(m) > 1 {
		return m[1]
	}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return truncate(line, 80)
		}
	}
	return ""
}

// ScannerNames returns all registered scanner names.
func (r *Registry) ScannerNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.entries))
	for n := range r.entries {
		names = append(names, n)
	}
	return names
}

const scannerSelect = `SELECT id, name, display_name, description, version, executable,
	adapter, enabled, asset_types, capabilities, manifest, status, status_detail,
	last_checked_at, documentation, created_at, updated_at
	FROM scanners`

func scanScannerRecord(row pgx.Row) (models.ScannerRecord, error) {
	var rec models.ScannerRecord
	err := row.Scan(&rec.ID, &rec.Name, &rec.DisplayName, &rec.Description, &rec.Version,
		&rec.Executable, &rec.Adapter, &rec.Enabled, &rec.AssetTypes, &rec.Capabilities,
		&rec.Manifest, &rec.Status, &rec.StatusDetail, &rec.LastChecked, &rec.Documentation,
		&rec.CreatedAt, &rec.UpdatedAt)
	if err != nil {
		return models.ScannerRecord{}, fmt.Errorf("registry: scan scanner record: %w", err)
	}
	return rec, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
