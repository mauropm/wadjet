package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
)

// Errors returned by the asset domain.
var (
	// ErrInvalidIdentity marks input that cannot become a canonical identity.
	ErrInvalidIdentity = errors.New("invalid asset identity")
	// ErrConflict means an asset with the same identity already exists.
	ErrConflict = errors.New("asset already exists")
	// ErrInvalidInput marks malformed request payloads.
	ErrInvalidInput = errors.New("invalid asset input")
)

// Querier is implemented by both *database.DB (through the embedded pool) and
// pgx.Tx, so every repository function can run standalone or inside a
// transaction owned by a caller — the findings ingestion pipeline needs the
// latter to keep an entire scan result atomic.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// assetCols renders the inet columns with host(): inet comes back in binary
// format and pgx cannot decode it into the *string fields of models.Asset,
// while host() yields the canonical address text the contract specifies.
const assetCols = `id, project_id, identity, asset_type, host(ip) AS ip, host(ipv6) AS ipv6, hostname, domain, mac,
	os_name, os_accuracy, status, discovery_source, description, tags,
	first_seen, last_seen, created_at, updated_at`

func scanAsset(row pgx.Row) (models.Asset, error) {
	var a models.Asset
	err := row.Scan(&a.ID, &a.ProjectID, &a.Identity, &a.AssetType, &a.IP, &a.IPv6,
		&a.Hostname, &a.Domain, &a.MAC, &a.OSName, &a.OSAccuracy, &a.Status,
		&a.DiscoverySource, &a.Description, &a.Tags, &a.FirstSeen, &a.LastSeen,
		&a.CreatedAt, &a.UpdatedAt)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return a, err
}

const observationCols = `id, asset_id, scan_session_id, scanner_execution_id, observation_type,
	observed_at, raw, source, created_at`

func scanObservation(row pgx.Row) (models.AssetObservation, error) {
	var o models.AssetObservation
	err := row.Scan(&o.ID, &o.AssetID, &o.ScanSessionID, &o.ScannerExecutionID,
		&o.ObservationType, &o.ObservedAt, &o.Raw, &o.Source, &o.CreatedAt)
	if len(o.Raw) == 0 {
		o.Raw = json.RawMessage(`{}`)
	}
	return o, err
}

// ───────────────────────────────────────────── scan ingestion

// UpsertFromScanTx merges one scanner observation into the asset inventory.
//
// Matching is on (project_id, identity) after normalising the reported
// identity, so a scanner that reports "2001:DB8::1" refreshes the asset created
// for "2001:db8::1". The rules are deliberately conservative because this runs
// inside another caller's transaction:
//
//   - unknown identity        -> insert the asset (discovery_source 'scanner')
//   - known identity          -> last_seen/updated_at are refreshed and only
//     empty columns are filled in (COALESCE): an address, MAC, OS or host name
//     that is already known is never overwritten and never blanked out, even
//     when this scanner did not report it
//   - always                  -> one append-only asset_observations row keeps
//     the full observation as raw JSON
//
// Tags are operator-owned and are therefore never touched here.
func (s *Service) UpsertFromScanTx(ctx context.Context, q Querier, projectID, sessionID, executionID uuid.UUID,
	scannerName string, obs scanners.AssetObservationData) (*models.Asset, bool, error) {

	identity, inferredType, err := NormalizeIdentity(obs.Identity)
	if err != nil {
		return nil, false, err
	}

	var ip, ipv6, mac, osName, hostname, domain any
	if obs.IPv4 != "" {
		if a, err := netipParse(obs.IPv4); err == nil {
			ip = a.String()
		}
	}
	if obs.IPv6 != "" {
		if a, err := netipParse(obs.IPv6); err == nil {
			ipv6 = a.String()
		}
	}
	if obs.MAC != "" {
		mac = strings.ToLower(strings.TrimSpace(obs.MAC))
	}
	if obs.OSName != "" {
		osName = obs.OSName
	}
	if len(obs.Hostnames) > 0 {
		if h, _, err := NormalizeIdentity(obs.Hostnames[0]); err == nil {
			hostname = h
			if d := domainOf(h); d != "" {
				domain = d
			}
		}
	}
	var osAccuracy any
	if obs.OSAccuracy > 0 {
		osAccuracy = obs.OSAccuracy
	}

	raw, err := json.Marshal(obs)
	if err != nil {
		return nil, false, fmt.Errorf("encode observation: %w", err)
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}

	asset, created, err := upsertAssetRow(ctx, q, projectID, identity, inferredType, ip, ipv6, mac, osName, osAccuracy, hostname, domain)
	if err != nil {
		return nil, false, err
	}

	_, err = q.Exec(ctx,
		`INSERT INTO asset_observations
		 (asset_id, scan_session_id, scanner_execution_id, observation_type, raw, source)
		 VALUES ($1, $2, $3, 'network', $4, $5)`,
		asset.ID, nullable(sessionID), nullable(executionID), raw, scannerName)
	if err != nil {
		return nil, false, fmt.Errorf("insert asset observation: %w", err)
	}

	// Scan activity keeps the project's activity stamp current.
	if _, err := q.Exec(ctx, `UPDATE projects SET last_activity_at = now() WHERE id = $1`, projectID); err != nil {
		return nil, false, fmt.Errorf("touch project activity: %w", err)
	}
	return asset, created, nil
}

// UpsertFromScan is the standalone (own-transaction) form of UpsertFromScanTx,
// for importers and ad-hoc callers.
func (s *Service) UpsertFromScan(ctx context.Context, projectID, sessionID, executionID uuid.UUID,
	scannerName string, obs scanners.AssetObservationData) (*models.Asset, bool, error) {

	var (
		asset   *models.Asset
		created bool
	)
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		var err error
		asset, created, err = s.UpsertFromScanTx(ctx, tx, projectID, sessionID, executionID, scannerName, obs)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return asset, created, nil
}

// upsertAssetRow inserts the asset when the identity is new, otherwise fills
// in only the columns the scanner actually reported.
func upsertAssetRow(ctx context.Context, q Querier, projectID uuid.UUID, identity, inferredType string,
	ip, ipv6, mac, osName, osAccuracy, hostname, domain any) (*models.Asset, bool, error) {

	row := q.QueryRow(ctx,
		`INSERT INTO assets
		 (project_id, identity, asset_type, ip, ipv6, hostname, domain, mac, os_name, os_accuracy,
		  status, discovery_source, first_seen, last_seen, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', 'scanner', now(), now(), now())
		 ON CONFLICT (project_id, identity) DO NOTHING
		 RETURNING `+assetCols,
		projectID, identity, inferredType, ip, ipv6, hostname, domain, mac, osName, osAccuracy)

	asset, err := scanAsset(row)
	switch {
	case err == nil:
		return &asset, true, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, false, fmt.Errorf("insert asset: %w", err)
	}

	// Existing asset: refresh the timestamp and fill only what was reported.
	row = q.QueryRow(ctx,
		`UPDATE assets SET
			ip          = COALESCE(ip, $2),
			ipv6        = COALESCE(ipv6, $3),
			mac         = COALESCE(mac, $4),
			os_name     = COALESCE(os_name, $5),
			os_accuracy = COALESCE(os_accuracy, $6),
			hostname    = COALESCE(hostname, $7),
			domain      = COALESCE(domain, $8),
			last_seen   = now(),
			updated_at  = now()
		 WHERE project_id = $1 AND identity = $9
		 RETURNING `+assetCols,
		projectID, ip, ipv6, mac, osName, osAccuracy, hostname, domain, identity)
	asset, err = scanAsset(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, ErrNotFound
		}
		return nil, false, fmt.Errorf("refresh asset: %w", err)
	}
	return &asset, false, nil
}

// FindByProjectIdentityTx looks an asset up by its canonical identity inside a
// caller's transaction. It returns ErrNotFound when the asset is unknown, which
// the findings pipeline treats as a per-finding error rather than a failure of
// the whole ingest.
func (s *Service) FindByProjectIdentityTx(ctx context.Context, q Querier, projectID uuid.UUID, rawIdentity string) (*models.Asset, error) {
	identity, _, err := NormalizeIdentity(rawIdentity)
	if err != nil {
		return nil, err
	}
	asset, err := scanAsset(q.QueryRow(ctx,
		`SELECT `+assetCols+` FROM assets WHERE project_id = $1 AND identity = $2`, projectID, identity))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &asset, nil
}

// ───────────────────────────────────────────── queries

// Get loads one asset by id.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Asset, error) {
	asset, err := scanAsset(s.db.QueryRow(ctx, `SELECT `+assetCols+` FROM assets WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &asset, nil
}

// LatestObservation returns the most recent observation of an asset, which is
// what the current asset view is derived from. It returns (nil, nil) when the
// asset exists but has never been observed.
func (s *Service) LatestObservation(ctx context.Context, assetID uuid.UUID) (*models.AssetObservation, error) {
	o, err := scanObservation(s.db.QueryRow(ctx,
		`SELECT `+observationCols+` FROM asset_observations
		 WHERE asset_id = $1 ORDER BY observed_at DESC, created_at DESC, id DESC LIMIT 1`, assetID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &o, nil
}

// History returns an asset's observations, newest first.
func (s *Service) History(ctx context.Context, assetID uuid.UUID, limit int, observationType string) ([]models.AssetObservation, error) {
	if _, err := s.Get(ctx, assetID); err != nil {
		return nil, err
	}
	args := []any{assetID}
	where := "asset_id = $1"
	if observationType != "" {
		if !validObservationType(observationType) {
			return nil, ErrInvalidInput
		}
		args = append(args, observationType)
		where += ` AND observation_type = $2`
	}
	args = append(args, clampInt(limit, 100, 1, 1000))
	rows, err := s.db.Query(ctx,
		`SELECT `+observationCols+` FROM asset_observations WHERE `+where+
			` ORDER BY observed_at DESC, created_at DESC, id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	return collect(rows, err, scanObservation)
}

// ProjectObservation is an observation paired with the asset it belongs to, as
// returned by the project-wide history endpoint.
type ProjectObservation struct {
	models.AssetObservation
	AssetIdentity string `json:"asset_identity"`
	AssetType     string `json:"asset_type"`
}

// RecentObservations returns the newest observations across every asset of a
// project, optionally narrowed to one asset and one observation type.
func (s *Service) RecentObservations(ctx context.Context, projectID uuid.UUID, limit int, observationType string, assetID *uuid.UUID) ([]ProjectObservation, error) {
	args := []any{projectID}
	where := "a.project_id = $1"
	if assetID != nil {
		args = append(args, *assetID)
		where += fmt.Sprintf(" AND ao.asset_id = $%d", len(args))
	}
	if observationType != "" {
		if !validObservationType(observationType) {
			return nil, ErrInvalidInput
		}
		args = append(args, observationType)
		where += fmt.Sprintf(" AND ao.observation_type = $%d", len(args))
	}
	args = append(args, clampInt(limit, 100, 1, 1000))

	rows, err := s.db.Query(ctx,
		`SELECT ao.id, ao.asset_id, ao.scan_session_id, ao.scanner_execution_id, ao.observation_type,
		        ao.observed_at, ao.raw, ao.source, ao.created_at, a.identity, a.asset_type
		   FROM asset_observations ao
		   JOIN assets a ON a.id = ao.asset_id
		  WHERE `+where+`
		  ORDER BY ao.observed_at DESC, ao.created_at DESC, ao.id DESC
		  LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProjectObservation{}
	for rows.Next() {
		var o ProjectObservation
		if err := rows.Scan(&o.ID, &o.AssetID, &o.ScanSessionID, &o.ScannerExecutionID, &o.ObservationType,
			&o.ObservedAt, &o.Raw, &o.Source, &o.CreatedAt, &o.AssetIdentity, &o.AssetType); err != nil {
			return nil, err
		}
		if len(o.Raw) == 0 {
			o.Raw = json.RawMessage(`{}`)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ListFilters narrows the asset inventory query.
type ListFilters struct {
	Query  string // ILIKE over identity, hostname, domain, description, tags
	Type   string
	Status string
	Source string
	Limit  int
	Offset int
	Sort   string
	Desc   bool
}

// List returns the project's inventory plus the total match count.
func (s *Service) List(ctx context.Context, projectID uuid.UUID, f ListFilters) ([]models.Asset, int, error) {
	var conds []string
	var args []any
	args = append(args, projectID)
	conds = append(conds, "project_id = $1")
	add := func(cond string, arg any) {
		base := len(args)
		n := strings.Count(cond, "?")
		for i := 0; i < n; i++ {
			cond = strings.Replace(cond, "?", fmt.Sprintf("$%d", base+i+1), 1)
			args = append(args, arg)
		}
		conds = append(conds, cond)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + escapeLike(q) + "%"
		add(`(identity ILIKE ? OR hostname ILIKE ? OR domain ILIKE ? OR description ILIKE ?
		      OR EXISTS (SELECT 1 FROM unnest(tags) AS t(tag) WHERE t.tag ILIKE ?))`, like)
	}
	if f.Type != "" {
		if !validAssetType(f.Type) {
			return nil, 0, ErrInvalidInput
		}
		add("asset_type = ?", f.Type)
	}
	if f.Status != "" {
		if !validStatus(f.Status) {
			return nil, 0, ErrInvalidInput
		}
		add("status = ?", f.Status)
	}
	if f.Source != "" {
		if f.Source != models.DiscoveryManual && f.Source != models.DiscoveryScanner && f.Source != models.DiscoveryImport {
			return nil, 0, ErrInvalidInput
		}
		add("discovery_source = ?", f.Source)
	}
	where := strings.Join(conds, " AND ")

	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM assets WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	orderBy, ok := assetSort(f.Sort, f.Desc)
	if !ok {
		return nil, 0, ErrInvalidInput
	}
	args = append(args, clampInt(f.Limit, 100, 1, 1000), clampInt(f.Offset, 0, 0, 1<<31-1))
	rows, err := s.db.Query(ctx,
		`SELECT `+assetCols+` FROM assets WHERE `+where+` ORDER BY `+orderBy+
			fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	items, err := collect(rows, err, scanAsset)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// collect drains rows through a scanner into a slice.
func collect[T any](rows pgx.Rows, err error, scan func(pgx.Row) (T, error)) ([]T, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func assetSort(field string, desc bool) (string, bool) {
	if field == "" {
		field = "last_seen"
	}
	col, ok := map[string]string{
		"last_seen":  "last_seen",
		"first_seen": "first_seen",
		"identity":   "identity",
		"asset_type": "asset_type",
		"status":     "status",
		"hostname":   "hostname",
		"created_at": "created_at",
	}[field]
	if !ok {
		return "", false
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return col + " " + dir + ", id ASC", true
}

func nullable(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
