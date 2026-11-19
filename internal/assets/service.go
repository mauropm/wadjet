// Package assets maintains the persistent host inventory of a project: the
// assets themselves, their append-only observation history and the "current
// view" derived from the latest observation.
//
// Ownership: Agent 3.
//
// Identity is the dedup key: assets.identity holds a normalised IP address in
// canonical text form, or a lower-cased host name, unique per project. Manual
// edits may change description, tags, status and the descriptive columns, but
// never the identity — that would break every observation attached to it.
//
// Scan ingestion (UpsertFromScan / UpsertFromScanTx) is the entry point used by
// the findings pipeline; see repository.go for the never-blank-out-what-we-know
// refresh rules.
package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

// Service provides asset operations and the /assets HTTP surface.
type Service struct {
	db *database.DB
}

// NewService builds the asset service.
func NewService(db *database.DB) *Service { return &Service{db: db} }

// Register mounts the asset routes on the /api/v1 router.
func (s *Service) Register(r chi.Router) {
	r.Get("/projects/{id}/assets", s.handleList)
	r.Post("/projects/{id}/assets", s.handleCreate)
	r.Get("/projects/{id}/observations", s.handleProjectObservations)
	r.Get("/assets/{id}", s.handleGet)
	r.Put("/assets/{id}", s.handleUpdate)
	r.Delete("/assets/{id}", s.handleDelete)
	r.Get("/assets/{id}/history", s.handleHistory)
}

// ───────────────────────────────────────────── manual CRUD

// CreateInput is the service-level payload for a manually registered asset.
type CreateInput struct {
	// Identity is any accepted spelling: an IP literal, a host name or a URL.
	// It is normalised into assets.identity.
	Identity        string
	AssetType       string  // optional override of the detected type
	IP              *string // inet columns, canonical text
	IPv6            *string
	Hostname        *string
	Domain          *string
	MAC             *string
	OSName          *string
	OSAccuracy      *int
	Status          string
	Description     string
	Tags            []string
	DiscoverySource string
}

// Create registers an asset manually and records a 'manual' observation.
func (s *Service) Create(ctx context.Context, projectID uuid.UUID, in CreateInput) (*models.Asset, error) {
	identity, inferred, err := NormalizeIdentity(in.Identity)
	if err != nil {
		return nil, err
	}
	assetType := inferred
	if in.AssetType != "" {
		if !validAssetType(in.AssetType) {
			return nil, fmt.Errorf("%w: unknown asset_type %q", ErrInvalidInput, in.AssetType)
		}
		assetType = in.AssetType
	}
	status := in.Status
	if status == "" {
		status = "active"
	}
	if !validStatus(status) {
		return nil, fmt.Errorf("%w: unknown status %q", ErrInvalidInput, status)
	}
	source := in.DiscoverySource
	if source == "" {
		source = models.DiscoveryManual
	}
	if source != models.DiscoveryManual && source != models.DiscoveryImport && source != models.DiscoveryScanner {
		return nil, fmt.Errorf("%w: unknown discovery_source %q", ErrInvalidInput, source)
	}

	var asset models.Asset
	err = s.db.InTx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`INSERT INTO assets
			 (project_id, identity, asset_type, ip, ipv6, hostname, domain, mac, os_name, os_accuracy,
			  status, discovery_source, description, tags, first_seen, last_seen, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now(),now(),now(),now())
			 RETURNING `+assetCols,
			projectID, identity, assetType, in.IP, in.IPv6, in.Hostname, in.Domain, in.MAC,
			in.OSName, in.OSAccuracy, status, source, in.Description, normalizeTags(in.Tags))
		a, err := scanAsset(row)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			if isMissingRelation(err) {
				return ErrNotFound
			}
			return err
		}
		asset = a
		raw, err := json.Marshal(map[string]any{
			"action":     "created",
			"identity":   identity,
			"asset_type": assetType,
			"request":    in,
		})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO asset_observations (asset_id, observation_type, raw, source)
			 VALUES ($1, 'manual', $2, 'manual')`, asset.ID, raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &asset, nil
}

// UpdateInput carries optional fields; nil means "leave unchanged". Identity,
// ip and ipv6 are not updatable: they are the dedup key and every observation
// history depends on them.
type UpdateInput struct {
	AssetType   *string
	Hostname    *string
	Domain      *string
	MAC         *string
	OSName      *string
	OSAccuracy  *int
	Status      *string
	Description *string
	Tags        *[]string // merged with the existing tags
}

// Update edits the descriptive fields of an asset and records a 'manual'
// observation describing the change.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*models.Asset, error) {
	sets := []string{"updated_at = now()"}
	var args []any
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if in.AssetType != nil {
		if !validAssetType(*in.AssetType) {
			return nil, fmt.Errorf("%w: unknown asset_type %q", ErrInvalidInput, *in.AssetType)
		}
		add("asset_type", *in.AssetType)
	}
	if in.Hostname != nil {
		h, _, err := NormalizeIdentity(*in.Hostname)
		if err != nil {
			return nil, err
		}
		add("hostname", h)
	}
	if in.Domain != nil {
		d, _, err := NormalizeIdentity(*in.Domain)
		if err != nil {
			return nil, err
		}
		add("domain", d)
	}
	if in.MAC != nil {
		add("mac", strings.ToLower(strings.TrimSpace(*in.MAC)))
	}
	if in.OSName != nil {
		add("os_name", *in.OSName)
	}
	if in.OSAccuracy != nil {
		if *in.OSAccuracy < 0 || *in.OSAccuracy > 100 {
			return nil, fmt.Errorf("%w: os_accuracy must be 0..100", ErrInvalidInput)
		}
		add("os_accuracy", *in.OSAccuracy)
	}
	if in.Status != nil {
		if !validStatus(*in.Status) {
			return nil, fmt.Errorf("%w: unknown status %q", ErrInvalidInput, *in.Status)
		}
		add("status", *in.Status)
	}
	if in.Description != nil {
		add("description", *in.Description)
	}
	if in.Tags != nil {
		// Manual edits merge tags; scanner ingestion never touches them.
		existing, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		add("tags", normalizeTags(append(append([]string{}, existing.Tags...), *in.Tags...)))
	}
	args = append(args, id)

	var asset models.Asset
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`UPDATE assets SET `+strings.Join(sets, ", ")+` WHERE id = $`+fmt.Sprint(len(args))+
				` RETURNING `+assetCols, args...)
		a, err := scanAsset(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		asset = a
		if len(sets) == 1 {
			return nil // nothing but updated_at: no history entry
		}
		raw, err := json.Marshal(map[string]any{"action": "updated", "changes": in})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO asset_observations (asset_id, observation_type, raw, source)
			 VALUES ($1, 'manual', $2, 'manual')`, asset.ID, raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &asset, nil
}

// Delete removes an asset and, by cascade, its observations.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM assets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ───────────────────────────────────────────── current view

// OpenPort is one entry of the computed open-port summary of the current view.
type OpenPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol,omitempty"`
	State     string `json:"state,omitempty"`
	Service   string `json:"service,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`
}

// AssetView is an asset plus the current view derived from its latest
// observation.
type AssetView struct {
	models.Asset
	// LatestObservation is the newest asset_observations row, raw scanner
	// payload included. Nil when the asset was never observed.
	LatestObservation *models.AssetObservation `json:"latest_observation,omitempty"`
	// LatestObservationRaw repeats observation.raw for clients that only need
	// the scanner payload.
	LatestObservationRaw json.RawMessage `json:"latest_observation_raw,omitempty"`
	// OpenPorts is computed from the ports reported by the latest observation.
	OpenPorts []OpenPort `json:"open_ports"`
}

// View returns an asset with its latest observation and the open-port summary.
func (s *Service) View(ctx context.Context, id uuid.UUID) (*AssetView, error) {
	asset, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.viewOf(ctx, asset)
}

func (s *Service) viewOf(ctx context.Context, asset *models.Asset) (*AssetView, error) {
	view := &AssetView{Asset: *asset, OpenPorts: []OpenPort{}}
	obs, err := s.LatestObservation(ctx, asset.ID)
	if err != nil {
		return nil, err
	}
	if obs == nil {
		return view, nil
	}
	view.LatestObservation = obs
	view.LatestObservationRaw = obs.Raw
	view.OpenPorts = openPorts(obs.Raw)
	return view, nil
}

// openPorts extracts the ports whose state is open from a raw observation.
// Anything unparseable yields an empty summary rather than an error: the
// summary is a convenience, the raw payload is the record.
func openPorts(raw json.RawMessage) []OpenPort {
	out := []OpenPort{}
	if len(raw) == 0 {
		return out
	}
	var payload struct {
		Ports []struct {
			Port      int    `json:"port"`
			Protocol  string `json:"protocol"`
			State     string `json:"state"`
			Service   string `json:"service"`
			Product   string `json:"product"`
			Version   string `json:"version"`
			ExtraInfo string `json:"extra_info"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out
	}
	for _, p := range payload.Ports {
		if !strings.EqualFold(p.State, "open") {
			continue
		}
		out = append(out, OpenPort{
			Port: p.Port, Protocol: strings.ToLower(p.Protocol), State: strings.ToLower(p.State),
			Service: p.Service, Product: p.Product, Version: p.Version, ExtraInfo: p.ExtraInfo,
		})
	}
	return out
}

// ───────────────────────────────────────────── HTTP

type createAssetRequest struct {
	Identity        string   `json:"identity"`
	AssetType       string   `json:"asset_type"`
	IP              *string  `json:"ip"`
	IPv6            *string  `json:"ipv6"`
	Hostname        *string  `json:"hostname"`
	Domain          *string  `json:"domain"`
	MAC             *string  `json:"mac"`
	OSName          *string  `json:"os_name"`
	OSAccuracy      *int     `json:"os_accuracy"`
	Status          string   `json:"status"`
	Description     string   `json:"description"`
	Tags            []string `json:"tags"`
	DiscoverySource string   `json:"discovery_source"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body createAssetRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	asset, err := s.Create(r.Context(), projectID, CreateInput{
		Identity: body.Identity, AssetType: body.AssetType, IP: body.IP, IPv6: body.IPv6,
		Hostname: body.Hostname, Domain: body.Domain, MAC: body.MAC, OSName: body.OSName,
		OSAccuracy: body.OSAccuracy, Status: body.Status, Description: body.Description,
		Tags: body.Tags, DiscoverySource: body.DiscoverySource,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	view, err := s.viewOf(r.Context(), asset)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusCreated, view)
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q := r.URL.Query()
	desc := !strings.EqualFold(q.Get("order"), "asc")
	items, total, err := s.List(r.Context(), projectID, ListFilters{
		Query:  q.Get("q"),
		Type:   q.Get("type"),
		Status: q.Get("status"),
		Source: q.Get("source"),
		Sort:   q.Get("sort"),
		Desc:   desc,
		Limit:  intQuery(r, "limit", 100),
		Offset: intQuery(r, "offset", 0),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteList(w, items, total)
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	view, err := s.View(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	// VER-002: when callers state a project scope, enforce it.
	if !api.ProjectScopeMatches(r, view.Asset.ProjectID) {
		api.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	api.WriteJSON(w, http.StatusOK, view)
}

// updateAssetRequest deliberately has no identity, ip or ipv6 field: the
// identity is immutable once an asset exists.
type updateAssetRequest struct {
	AssetType   *string   `json:"asset_type"`
	Hostname    *string   `json:"hostname"`
	Domain      *string   `json:"domain"`
	MAC         *string   `json:"mac"`
	OSName      *string   `json:"os_name"`
	OSAccuracy  *int      `json:"os_accuracy"`
	Status      *string   `json:"status"`
	Description *string   `json:"description"`
	Tags        *[]string `json:"tags"`
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if existing, err := s.Get(r.Context(), id); err == nil &&
		!api.ProjectScopeMatches(r, existing.ProjectID) {
		api.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	var body updateAssetRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	asset, err := s.Update(r.Context(), id, UpdateInput{
		AssetType: body.AssetType, Hostname: body.Hostname, Domain: body.Domain, MAC: body.MAC,
		OSName: body.OSName, OSAccuracy: body.OSAccuracy, Status: body.Status,
		Description: body.Description, Tags: body.Tags,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, asset)
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if existing, err := s.Get(r.Context(), id); err == nil &&
		!api.ProjectScopeMatches(r, existing.ProjectID) {
		api.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.Delete(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Service) handleHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if existing, err := s.Get(r.Context(), id); err == nil &&
		!api.ProjectScopeMatches(r, existing.ProjectID) {
		api.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	items, err := s.History(r.Context(), id, intQuery(r, "limit", 100), r.URL.Query().Get("type"))
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteList(w, items, len(items))
}

func (s *Service) handleProjectObservations(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var assetFilter *uuid.UUID
	if raw := r.URL.Query().Get("asset_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			api.WriteError(w, http.StatusBadRequest, "invalid asset_id")
			return
		}
		assetFilter = &parsed
	}
	items, err := s.RecentObservations(r.Context(), projectID, intQuery(r, "limit", 100),
		r.URL.Query().Get("type"), assetFilter)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteList(w, items, len(items))
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		api.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		api.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrInvalidIdentity), errors.Is(err, ErrInvalidInput):
		api.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		api.WriteError(w, http.StatusInternalServerError, "asset operation failed")
	}
}

func pathUUID(w http.ResponseWriter, r *http.Request, key string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, key))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid "+key)
		return uuid.Nil, false
	}
	return id, true
}

func intQuery(r *http.Request, key string, def int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func clampInt(v, def, min, max int) int {
	if v < min {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func normalizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		k := strings.ToLower(t)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, t)
		if len(out) >= 64 {
			break
		}
	}
	return out
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key value")
}

func isMissingRelation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "violates foreign key")
}

// netipParse canonicalises an address reported by a scanner; invalid text is
// dropped rather than failing the whole observation.
func netipParse(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.Unmap(), nil
}
