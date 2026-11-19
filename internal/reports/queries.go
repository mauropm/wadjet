package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

// ErrNotFound is returned by loaders when a referenced row does not exist;
// handlers map it to HTTP 404.
var ErrNotFound = errors.New("not found")

// findingColumnList is the shared projection for findings joined with their
// asset and their per-project sequence number (used for FND-<n> labels).
const findingColumns = `
	f.id, f.project_id, f.asset_id, f.title, f.description, f.technical_details,
	f.evidence, f.scanner, f.port, f.protocol, f.service, f.cves, f.cvss_score,
	f.severity, f.status, f.remediation, f."references", f.fingerprint,
	f.first_detected, f.last_detected, f.created_at, f.updated_at,
	r.seq, a.identity, a.asset_type, a.ip::text, a.hostname`

// findingFromRow scans a row produced by findingColumns into a findingView.
func findingFromRow(scan func(dest ...any) error) (findingView, error) {
	var (
		f    findingView
		port *int
		prot *string
		svc  *string
		ip   *string
	)
	err := scan(
		&f.ID, &f.ProjectID, &f.AssetID, &f.Title, &f.Description, &f.TechnicalDetails,
		&f.Evidence, &f.Scanner, &port, &prot, &svc, &f.CVEs, &f.CVSSScore,
		&f.Severity, &f.Status, &f.Remediation, &f.References, &f.Fingerprint,
		&f.FirstDetected, &f.LastDetected, &f.CreatedAt, &f.UpdatedAt,
		&f.Seq, &f.AssetIdentity, &f.AssetType, &ip, &f.AssetHostname,
	)
	f.Port, f.Protocol, f.Service, f.AssetIP = port, prot, svc, ip
	return f, err
}

// findingView is a finding enriched for rendering: sequence label, asset
// summary and parsed, sanitized display text.
type findingView struct {
	models.Finding
	Seq           int
	AssetIdentity string
	AssetType     string
	AssetIP       *string
	AssetHostname *string

	StatusHistory []models.FindingStatusHistory
	Detections    []Detection
}

// Detection is one recorded detection event of a finding.
type Detection struct {
	ObservedAt time.Time
	Status     string
	Scanner    string
}

// Label is the human-facing finding identifier, e.g. FND-7.
func (f findingView) Label() string { return fmt.Sprintf("FND-%d", f.Seq) }

// Service returns the service name or a neutral fallback for display.
func (f findingView) ServiceOrDash() string {
	if f.Service != nil && *f.Service != "" {
		return collapseWhitespace(*f.Service)
	}
	return "—"
}

// PortText renders the port/protocol pair for display.
func (f findingView) PortText() string {
	if f.Port == nil {
		return "—"
	}
	if f.Protocol != nil && *f.Protocol != "" {
		return fmt.Sprintf("%d/%s", *f.Port, collapseWhitespace(*f.Protocol))
	}
	return fmt.Sprintf("%d", *f.Port)
}

// AssetText renders "identity (ip)" for display.
func (f findingView) AssetText() string {
	if f.AssetIP != nil && *f.AssetIP != "" {
		return collapseWhitespace(f.AssetIdentity) + " (" + *f.AssetIP + ")"
	}
	return collapseWhitespace(f.AssetIdentity)
}

// ReferencesList parses the references JSONB defensively: an array of
// strings, an array of objects with a "url" member, or raw text lines that
// look like URLs.
func (f findingView) ReferencesList() []string {
	raw := bytesOf(f.References)
	if len(raw) == 0 {
		return nil
	}
	var out []string
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, s := range arr {
			if s = strings.TrimSpace(sanitizeText(s)); s != "" {
				out = append(out, capText(s, 500))
			}
		}
		return out
	}
	var objs []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objs); err == nil {
		for _, o := range objs {
			for _, key := range []string{"url", "href", "link", "value"} {
				if v, ok := o[key]; ok {
					var s string
					if json.Unmarshal(v, &s) == nil {
						if s = strings.TrimSpace(sanitizeText(s)); s != "" {
							out = append(out, capText(s, 500))
						}
						break
					}
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			out = append(out, capText(collapseWhitespace(line), 500))
		}
	}
	return out
}

func bytesOf(raw json.RawMessage) []byte {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// assetView is an asset enriched with data from its most recent observation.
type assetView struct {
	models.Asset
	OpenPorts    int
	Ports        []observedPort
	LatestObsAt  *time.Time
	LatestSource string
}

// observedPort is one port/service entry parsed out of an observation's
// raw JSONB (scanner-native shape, defensively decoded).
type observedPort struct {
	Port     int
	Protocol string
	Service  string
	State    string
	Version  string
}

// observedPorts decodes the ports array of an observation payload. Both
// "ports" and "services" keys are accepted; unknown shapes are ignored.
func observedPorts(raw json.RawMessage) []observedPort {
	if len(raw) == 0 {
		return nil
	}
	var doc struct {
		Ports []struct {
			Port     *int   `json:"port"`
			Protocol string `json:"protocol"`
			Service  string `json:"service"`
			State    string `json:"state"`
			Version  string `json:"version"`
			Product  string `json:"product"`
		} `json:"ports"`
		Services []struct {
			Port     *int   `json:"port"`
			Protocol string `json:"protocol"`
			Service  string `json:"service"`
			State    string `json:"state"`
			Version  string `json:"version"`
			Product  string `json:"product"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []observedPort
	add := func(p *int, protocol, service, state, version, product string) {
		if p == nil || *p < 0 || *p > 65535 {
			return
		}
		if version == "" {
			version = product
		}
		key := fmt.Sprintf("%d/%s/%s", *p, protocol, state)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, observedPort{
			Port:     *p,
			Protocol: collapseWhitespace(protocol),
			Service:  collapseWhitespace(service),
			State:    collapseWhitespace(state),
			Version:  collapseWhitespace(capText(version, 200)),
		})
	}
	for _, p := range doc.Ports {
		add(p.Port, p.Protocol, p.Service, p.State, p.Version, p.Product)
	}
	for _, p := range doc.Services {
		add(p.Port, p.Protocol, p.Service, p.State, p.Version, p.Product)
	}
	return out
}

// executionView is a scanner execution prepared for rendering.
type executionView struct {
	models.ScannerExecution
	Version string // resolved scanner version (registry), may be empty
}

// scopeTarget is a row of the scope section.
type scopeTarget struct {
	Target   string
	Status   string
	Error    string
	Excluded bool
	Note     string
}

// obsSummary is one appendix row: observations per asset per type.
type obsSummary struct {
	Identity string
	Type     string
	Count    int
	LastAt   time.Time
}

// findingFilter narrows a findings query for consolidated reports.
type findingFilter struct {
	Severities []string
	AssetID    *uuid.UUID
	SessionID  *uuid.UUID
}

// ───────────────────────────────────────────── loaders

func loadProject(ctx context.Context, db *database.DB, id uuid.UUID) (models.Project, error) {
	var p models.Project
	err := db.QueryRow(ctx,
		`SELECT id, name, description, status, tags, settings, created_by, created_at, updated_at, last_activity_at
		 FROM projects WHERE id = $1`, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.Status, &p.Tags, &p.Settings,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.LastActivity)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func loadSession(ctx context.Context, db *database.DB, id uuid.UUID) (models.ScanSession, error) {
	var s models.ScanSession
	err := db.QueryRow(ctx,
		`SELECT id, project_id, profile_id, name, status, targets, scanner_names,
		        assets_processed, findings_created, findings_updated, error,
		        started_at, finished_at, duration_ms, created_by, created_at, updated_at
		 FROM scan_sessions WHERE id = $1`, id).
		Scan(&s.ID, &s.ProjectID, &s.ProfileID, &s.Name, &s.Status, &s.Targets, &s.ScannerNames,
			&s.AssetsProcessed, &s.FindingsCreated, &s.FindingsUpdated, &s.Error,
			&s.StartedAt, &s.FinishedAt, &s.DurationMS, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

func loadExecutions(ctx context.Context, db *database.DB, sessionID uuid.UUID) ([]executionView, error) {
	rows, err := db.Query(ctx,
		`SELECT id, session_id, scanner_name, status, config, targets, raw_output_path,
		        raw_output_bytes, assets_observed, findings_found, error, log,
		        started_at, finished_at, created_at
		 FROM scanner_executions WHERE session_id = $1
		 ORDER BY started_at NULLS LAST, created_at`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []executionView
	for rows.Next() {
		var e executionView
		if err := rows.Scan(&e.ID, &e.SessionID, &e.ScannerName, &e.Status, &e.Config, &e.Targets,
			&e.RawOutputPath, &e.RawOutputBytes, &e.AssetsObserved, &e.FindingsFound,
			&e.Error, &e.Log, &e.StartedAt, &e.FinishedAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Resolve scanner versions from the registry (best effort).
	if len(out) > 0 {
		names := make([]string, 0, len(out))
		for _, e := range out {
			names = append(names, e.ScannerName)
		}
		srows, err := db.Query(ctx, `SELECT name, version FROM scanners WHERE name = ANY($1)`, names)
		if err == nil {
			versions := map[string]string{}
			for srows.Next() {
				var n, v string
				if err := srows.Scan(&n, &v); err == nil {
					versions[n] = v
				}
			}
			srows.Err() // best effort
			for i := range out {
				out[i].Version = versions[out[i].ScannerName]
			}
		}
	}
	return out, nil
}

func loadScopeTargets(ctx context.Context, db *database.DB, sessionID, projectID uuid.UUID) ([]scopeTarget, error) {
	var out []scopeTarget
	rows, err := db.Query(ctx,
		`SELECT target, status, error, false, '' FROM scan_session_targets WHERE session_id = $1 ORDER BY target`, sessionID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t scopeTarget
		if err := rows.Scan(&t.Target, &t.Status, &t.Error, &t.Excluded, &t.Note); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = db.Query(ctx,
		`SELECT target, 'recorded', '', excluded, note FROM project_targets WHERE project_id = $1 ORDER BY excluded DESC, target`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t scopeTarget
		if err := rows.Scan(&t.Target, &t.Status, &t.Error, &t.Excluded, &t.Note); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func loadAssets(ctx context.Context, db *database.DB, projectID uuid.UUID, only *uuid.UUID) ([]assetView, error) {
	q := `SELECT id, project_id, identity, asset_type, ip::text, ipv6::text, hostname, domain,
	             mac, os_name, os_accuracy, status, discovery_source, description, tags,
	             first_seen, last_seen, created_at, updated_at
	      FROM assets WHERE project_id = $1`
	args := []any{projectID}
	if only != nil {
		q += ` AND id = $2`
		args = append(args, *only)
	}
	q += ` ORDER BY coalesce(ip::text, identity), identity`
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var out []assetView
	for rows.Next() {
		var a assetView
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Identity, &a.AssetType, &a.IP, &a.IPv6,
			&a.Hostname, &a.Domain, &a.MAC, &a.OSName, &a.OSAccuracy, &a.Status,
			&a.DiscoverySource, &a.Description, &a.Tags, &a.FirstSeen, &a.LastSeen,
			&a.CreatedAt, &a.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}

	// Attach the latest observation per asset (ports come from its raw JSONB).
	ids := make([]uuid.UUID, len(out))
	for i := range out {
		ids[i] = out[i].ID
	}
	orows, err := db.Query(ctx,
		`SELECT DISTINCT ON (asset_id) asset_id, observed_at, source, raw
		 FROM asset_observations WHERE asset_id = ANY($1::uuid[])
		 ORDER BY asset_id, observed_at DESC`, ids)
	if err != nil {
		return nil, err
	}
	defer orows.Close()
	for orows.Next() {
		var (
			assetID    uuid.UUID
			observedAt time.Time
			source     string
			raw        json.RawMessage
		)
		if err := orows.Scan(&assetID, &observedAt, &source, &raw); err != nil {
			return nil, err
		}
		for i := range out {
			if out[i].ID != assetID {
				continue
			}
			out[i].Ports = observedPorts(raw)
			out[i].LatestObsAt = &observedAt
			out[i].LatestSource = source
			for _, p := range out[i].Ports {
				if strings.EqualFold(p.State, "open") {
					out[i].OpenPorts++
				}
			}
		}
	}
	return out, orows.Err()
}

func loadFindings(ctx context.Context, db *database.DB, projectID uuid.UUID, flt findingFilter) ([]findingView, error) {
	q := `WITH ranked AS (
	        SELECT id, row_number() OVER (ORDER BY created_at, id) AS seq
	        FROM findings WHERE project_id = $1)
	      SELECT ` + findingColumns + `
	      FROM findings f
	      JOIN ranked r ON r.id = f.id
	      JOIN assets a ON a.id = f.asset_id
	      WHERE f.project_id = $1`
	args := []any{projectID}
	n := 2
	if len(flt.Severities) > 0 {
		q += fmt.Sprintf(` AND f.severity = ANY($%d)`, n)
		args = append(args, flt.Severities)
		n++
	}
	if flt.AssetID != nil {
		q += fmt.Sprintf(` AND f.asset_id = $%d`, n)
		args = append(args, *flt.AssetID)
		n++
	}
	if flt.SessionID != nil {
		q += fmt.Sprintf(` AND EXISTS (SELECT 1 FROM finding_observations fo
		        WHERE fo.finding_id = f.id AND fo.scan_session_id = $%d)`, n)
		args = append(args, *flt.SessionID)
		n++
	}
	q += ` ORDER BY CASE f.severity
	                   WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
	                   WHEN 'low' THEN 3 ELSE 4 END,
	               f.created_at, f.id`
	// SECURITY (SEC-007): hard cap on findings per generated report so a
	// project with tens of thousands of findings cannot turn one download
	// request into a multi-GB PDF/ZIP generation bomb.
	q += fmt.Sprintf(` LIMIT $%d`, n)
	args = append(args, maxFindingsPerReport)
	return queryFindings(ctx, db, q, args)
}

// maxFindingsPerReport bounds findings rendered into any single generated
// report (SEC-007 DoS bound). The API surfaces the cap in the report log.
const maxFindingsPerReport = 500

func loadFinding(ctx context.Context, db *database.DB, id uuid.UUID) (findingView, error) {
	q := `WITH ranked AS (
	        SELECT id, row_number() OVER (ORDER BY created_at, id) AS seq
	        FROM findings WHERE project_id = (SELECT project_id FROM findings WHERE id = $1))
	      SELECT ` + findingColumns + `
	      FROM findings f
	      JOIN ranked r ON r.id = f.id
	      JOIN assets a ON a.id = f.asset_id
	      WHERE f.id = $1`
	fs, err := queryFindings(ctx, db, q, []any{id})
	if err != nil {
		return findingView{}, err
	}
	if len(fs) == 0 {
		return findingView{}, ErrNotFound
	}
	f := fs[0]

	// Status history.
	rows, err := db.Query(ctx,
		`SELECT id, finding_id, from_status, to_status, changed_by, note, created_at
		 FROM finding_status_history WHERE finding_id = $1 ORDER BY created_at`, id)
	if err != nil {
		return f, err
	}
	for rows.Next() {
		var h models.FindingStatusHistory
		if err := rows.Scan(&h.ID, &h.FindingID, &h.FromStatus, &h.ToStatus, &h.ChangedBy, &h.Note, &h.CreatedAt); err != nil {
			rows.Close()
			return f, err
		}
		f.StatusHistory = append(f.StatusHistory, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return f, err
	}

	// Detection history with scanner attribution.
	rows, err = db.Query(ctx,
		`SELECT fo.observed_at, fo.status_at_detection, coalesce(se.scanner_name, '')
		 FROM finding_observations fo
		 LEFT JOIN scanner_executions se ON se.id = fo.scanner_execution_id
		 WHERE fo.finding_id = $1 ORDER BY fo.observed_at DESC LIMIT 100`, id)
	if err != nil {
		return f, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Detection
		if err := rows.Scan(&d.ObservedAt, &d.Status, &d.Scanner); err != nil {
			return f, err
		}
		f.Detections = append(f.Detections, d)
	}
	return f, rows.Err()
}

func queryFindings(ctx context.Context, db *database.DB, q string, args []any) ([]findingView, error) {
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findingView
	for rows.Next() {
		f, err := findingFromRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func loadObservationSummary(ctx context.Context, db *database.DB, projectID uuid.UUID) ([]obsSummary, error) {
	rows, err := db.Query(ctx,
		`SELECT a.identity, o.observation_type, count(*)::int, max(o.observed_at)
		 FROM asset_observations o
		 JOIN assets a ON a.id = o.asset_id
		 WHERE a.project_id = $1
		 GROUP BY a.identity, o.observation_type
		 ORDER BY a.identity, o.observation_type`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []obsSummary
	for rows.Next() {
		var s obsSummary
		if err := rows.Scan(&s.Identity, &s.Type, &s.Count, &s.LastAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
