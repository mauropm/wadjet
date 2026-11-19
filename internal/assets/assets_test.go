package assets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/assets/itest"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
)

func TestNormalizeIdentity(t *testing.T) {
	cases := []struct {
		raw      string
		want     string
		wantType string
		wantErr  bool
	}{
		{raw: "10.0.0.1", want: "10.0.0.1", wantType: models.AssetTypeIPv4},
		{raw: " 10.0.0.1 ", want: "10.0.0.1", wantType: models.AssetTypeIPv4},
		{raw: "010.000.000.001", wantErr: true}, // not a valid literal for netip
		{raw: "10.0.0.256", wantErr: true},
		{raw: "2001:DB8:0000::0001", want: "2001:db8::1", wantType: models.AssetTypeIPv6},
		{raw: "::ffff:10.0.0.5", want: "10.0.0.5", wantType: models.AssetTypeIPv4},
		{raw: "fe80::1%eth0", wantErr: true},
		{raw: "WWW.Example.COM", want: "www.example.com", wantType: models.AssetTypeHostname},
		{raw: "www.example.com.", want: "www.example.com", wantType: models.AssetTypeHostname},
		{raw: "https://Shop.Example.com:8443/cart?id=1", want: "shop.example.com", wantType: models.AssetTypeHostname},
		{raw: "http://10.0.0.9/login", want: "10.0.0.9", wantType: models.AssetTypeIPv4},
		{raw: "example.com:8080", want: "example.com", wantType: models.AssetTypeHostname},
		{raw: "[2001:db8::1]:8443", want: "2001:db8::1", wantType: models.AssetTypeIPv6},
		{raw: "intranet", want: "intranet", wantType: models.AssetTypeHostname},
		{raw: "_dmarc.example.com", want: "_dmarc.example.com", wantType: models.AssetTypeHostname},
		{raw: "10.0.0.0/24", wantErr: true}, // a range is not an asset
		{raw: "", wantErr: true},
		{raw: "   ", wantErr: true},
		{raw: "not a host", wantErr: true},
		{raw: "bad;char.com", wantErr: true},
		{raw: "double..dot.com", wantErr: true},
	}
	for _, tc := range cases {
		got, kind, err := NormalizeIdentity(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeIdentity(%q) = %q, want error", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeIdentity(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want || kind != tc.wantType {
			t.Errorf("NormalizeIdentity(%q) = (%q,%q), want (%q,%q)", tc.raw, got, kind, tc.want, tc.wantType)
		}
	}
}

// TestNormalizeIdentityIsStableAcrossSpellings is the property the whole
// inventory depends on: two spellings of the same host must dedupe to one row.
func TestNormalizeIdentityIsStableAcrossSpellings(t *testing.T) {
	groups := [][]string{
		{"2001:db8::1", "2001:DB8:0:0::1", "https://[2001:DB8::1]/", "[2001:db8::1]:443"},
		{"www.example.com", "WWW.Example.COM.", "https://www.example.com/path", "www.example.com:443"},
		{"::ffff:10.0.0.7", "10.0.0.7"},
	}
	for _, group := range groups {
		canonical, _, err := NormalizeIdentity(group[0])
		if err != nil {
			t.Fatalf("NormalizeIdentity(%q): %v", group[0], err)
		}
		for _, variant := range group[1:] {
			got, _, err := NormalizeIdentity(variant)
			if err != nil {
				t.Fatalf("NormalizeIdentity(%q): %v", variant, err)
			}
			if got != canonical {
				t.Errorf("%q normalised to %q, want %q", variant, got, canonical)
			}
		}
	}
}

func scanObs(identity string) scanners.AssetObservationData {
	return scanners.AssetObservationData{
		Identity:  identity,
		Hostnames: []string{"web-01.example.com"},
		Ports: []scanners.PortObservation{
			{Port: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH", Version: "8.9p1"},
			{Port: 80, Protocol: "tcp", State: "open", Service: "http"},
			{Port: 443, Protocol: "tcp", State: "closed"},
			{Port: 53, Protocol: "udp", State: "filtered"},
		},
	}
}

func TestUpsertFromScanCreatesAndRefreshes(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")
	session := itest.NewScanSession(t, project)
	exec := itest.NewExecution(t, session, "nmap")

	obs := scanObs("2001:DB8::0001")
	obs.IPv6 = "2001:db8::1"
	obs.MAC = "AA:BB:CC:DD:EE:FF"
	obs.OSName = "Linux 5.15"
	obs.OSAccuracy = 92

	asset, created, err := s.UpsertFromScan(ctx, project, session, exec, "nmap", obs)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !created {
		t.Fatal("first upsert should create the asset")
	}
	if asset.Identity != "2001:db8::1" {
		t.Fatalf("identity = %q, want canonical 2001:db8::1", asset.Identity)
	}
	if asset.AssetType != models.AssetTypeIPv6 || asset.DiscoverySource != models.DiscoveryScanner {
		t.Fatalf("asset = %+v", asset)
	}
	if asset.IPv6 == nil || *asset.IPv6 != "2001:db8::1" {
		t.Fatalf("ipv6 = %v", asset.IPv6)
	}
	if asset.MAC == nil || *asset.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("mac = %v, want lowercased", asset.MAC)
	}
	if asset.Hostname == nil || *asset.Hostname != "web-01.example.com" {
		t.Fatalf("hostname = %v", asset.Hostname)
	}
	if asset.Domain == nil || *asset.Domain != "example.com" {
		t.Fatalf("domain = %v, want example.com", asset.Domain)
	}
	if asset.OSAccuracy == nil || *asset.OSAccuracy != 92 {
		t.Fatalf("os_accuracy = %v", asset.OSAccuracy)
	}

	// Re-ingesting a different spelling of the same host must not create a
	// second row, must append one observation and must refresh last_seen.
	first := asset.LastSeen
	time.Sleep(15 * time.Millisecond)
	repeat := scanObs("2001:db8::1")
	second, created, err := s.UpsertFromScan(ctx, project, session, exec, "nmap", repeat)
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if created {
		t.Fatal("re-ingest created a duplicate asset")
	}
	if second.ID != asset.ID {
		t.Fatal("re-ingest returned a different asset id")
	}
	if !second.LastSeen.After(first) {
		t.Fatalf("last_seen not refreshed: %v -> %v", first, second.LastSeen)
	}
	if n := itest.Count(t, `SELECT count(*) FROM assets WHERE project_id = $1`, project); n != 1 {
		t.Fatalf("asset rows = %d, want 1", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM asset_observations WHERE asset_id = $1`, asset.ID); n != 2 {
		t.Fatalf("observation rows = %d, want 2", n)
	}

	// The raw payload of the observation is the full scanner data.
	var raw []byte
	if err := itest.DB().QueryRow(ctx,
		`SELECT raw FROM asset_observations WHERE asset_id = $1 ORDER BY observed_at DESC LIMIT 1`, asset.ID).Scan(&raw); err != nil {
		t.Fatalf("read raw: %v", err)
	}
	var decoded scanners.AssetObservationData
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("raw is not the observation JSON: %v", err)
	}
	if len(decoded.Ports) != 4 || decoded.Hostnames[0] != "web-01.example.com" {
		t.Fatalf("raw = %s", raw)
	}

	// Scan activity stamps the project.
	var activity *time.Time
	if err := itest.DB().QueryRow(ctx, `SELECT last_activity_at FROM projects WHERE id = $1`, project).Scan(&activity); err != nil {
		t.Fatalf("read activity: %v", err)
	}
	if activity == nil {
		t.Fatal("ingest did not stamp projects.last_activity_at")
	}
}

// TestUpsertFromScanNeverBlanksKnownData pins the conservative refresh rule.
func TestUpsertFromScanNeverBlanksKnownData(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")
	session := itest.NewScanSession(t, project)
	exec := itest.NewExecution(t, session, "nmap")

	// A manual asset already knows the hostname, OS and tags.
	manual, err := s.Create(ctx, project, CreateInput{
		Identity: "203.0.113.10", Hostname: strPtr("known.example.com"),
		OSName: strPtr("Debian 12"), OSAccuracy: intPtr(80), Tags: []string{"manual-tag"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A sparse scanner observation reports nothing but the identity.
	if _, _, err := s.UpsertFromScan(ctx, project, session, exec, "thin-scanner",
		scanners.AssetObservationData{Identity: "203.0.113.10"}); err != nil {
		t.Fatalf("sparse upsert: %v", err)
	}
	got, err := s.Get(ctx, manual.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Hostname == nil || *got.Hostname != "known.example.com" {
		t.Fatalf("hostname blanked by scan: %v", got.Hostname)
	}
	if got.OSName == nil || *got.OSName != "Debian 12" {
		t.Fatalf("os_name blanked by scan: %v", got.OSName)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "manual-tag" {
		t.Fatalf("scanner modified operator tags: %v", got.Tags)
	}
	if got.DiscoverySource != models.DiscoveryManual {
		t.Fatalf("discovery_source changed to %q", got.DiscoverySource)
	}

	// A richer scan fills in what was missing but keeps what was known.
	if _, _, err := s.UpsertFromScan(ctx, project, session, exec, "nmap", scanners.AssetObservationData{
		Identity: "203.0.113.10", MAC: "00:11:22:33:44:55", Hostnames: []string{"other.example.com"},
	}); err != nil {
		t.Fatalf("rich upsert: %v", err)
	}
	got, err = s.Get(ctx, manual.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MAC == nil || *got.MAC != "00:11:22:33:44:55" {
		t.Fatalf("mac not filled in: %v", got.MAC)
	}
	if *got.Hostname != "known.example.com" {
		t.Fatalf("hostname overwritten by a later scan: %v", got.Hostname)
	}
}

func TestUpsertFromScanRejectsBadIdentity(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")
	if _, _, err := s.UpsertFromScan(ctx, project, uuid.Nil, uuid.Nil, "nmap",
		scanners.AssetObservationData{Identity: "not a host!"}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("err = %v, want ErrInvalidIdentity", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM assets WHERE project_id = $1`, project); n != 0 {
		t.Fatalf("bad identity created %d assets", n)
	}
}

func TestFindByProjectIdentity(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")
	if _, _, err := s.UpsertFromScan(ctx, project, uuid.Nil, uuid.Nil, "nmap", scanObs("db.example.com")); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	asset, err := s.FindByProjectIdentityTx(ctx, itest.DB(), project, "DB.Example.COM.")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if asset.Identity != "db.example.com" {
		t.Fatalf("identity = %q", asset.Identity)
	}
	if _, err := s.FindByProjectIdentityTx(ctx, itest.DB(), project, "missing.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing lookup err = %v, want ErrNotFound", err)
	}
}

func TestManualAssetConflictAndImmutableIdentity(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")

	asset, err := s.Create(ctx, project, CreateInput{Identity: "198.51.100.7", Description: "jump box", Tags: []string{"edge"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// The same host in a different spelling is still a conflict.
	if _, err := s.Create(ctx, project, CreateInput{Identity: "198.51.100.7 "}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate err = %v, want ErrConflict", err)
	}
	// Same identity in a different project is fine.
	other := itest.NewProject(t, "")
	if _, err := s.Create(ctx, other, CreateInput{Identity: "198.51.100.7"}); err != nil {
		t.Fatalf("same identity in another project: %v", err)
	}
	if _, err := s.Create(ctx, uuid.New(), CreateInput{Identity: "198.51.100.8"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown project err = %v, want ErrNotFound", err)
	}
	if _, err := s.Create(ctx, project, CreateInput{Identity: "!!!"}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("bad identity err = %v", err)
	}
	if _, err := s.Create(ctx, project, CreateInput{Identity: "ok.example.com", Status: "bogus"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad status err = %v", err)
	}

	// Manual edits change description/tags/status/hostname but not the identity.
	newTags := []string{"edge", "dmz", "DMZ", ""}
	newStatus := "inactive"
	newDesc := "reviewed"
	host := "jump01.example.com"
	updated, err := s.Update(ctx, asset.ID, UpdateInput{Tags: &newTags, Status: &newStatus, Description: &newDesc, Hostname: &host})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Identity != asset.Identity {
		t.Fatalf("identity changed: %q -> %q", asset.Identity, updated.Identity)
	}
	if updated.Status != newStatus || updated.Description != newDesc {
		t.Fatalf("update ignored fields: %+v", updated)
	}
	if strings.Join(updated.Tags, ",") != "edge,dmz" {
		t.Fatalf("tags not merged and de-duplicated case-insensitively: %v", updated.Tags)
	}
	if updated.Hostname == nil || *updated.Hostname != "jump01.example.com" {
		t.Fatalf("hostname = %v", updated.Hostname)
	}
	// Tags merge with the existing set instead of replacing it.
	merged, err := s.Update(ctx, asset.ID, UpdateInput{Tags: &[]string{"newtag"}})
	if err != nil {
		t.Fatalf("merge tags: %v", err)
	}
	joined := strings.Join(merged.Tags, ",")
	for _, want := range []string{"edge", "dmz", "newtag"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("merged tags %q lost %q", joined, want)
		}
	}

	// The update also lands in the history as a manual observation.
	if n := itest.Count(t,
		`SELECT count(*) FROM asset_observations WHERE asset_id = $1 AND observation_type = 'manual'`, asset.ID); n == 0 {
		t.Fatal("manual edit recorded no observation")
	}
	if _, err := s.Update(ctx, uuid.New(), UpdateInput{Description: &newDesc}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing err = %v", err)
	}
	if err := s.Delete(ctx, asset.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Delete(ctx, asset.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete err = %v", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM asset_observations WHERE asset_id = $1`, asset.ID); n != 0 {
		t.Fatal("observations survived asset delete")
	}
}

func TestLatestObservationAndOpenPorts(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")
	session := itest.NewScanSession(t, project)
	exec := itest.NewExecution(t, session, "nmap")

	// An asset that has never been observed must still be viewable. A row
	// inserted behind the API has no history: a manual Create records a
	// 'manual' bookkeeping observation, so it is not an empty fixture.
	var bare uuid.UUID
	if err := itest.DB().QueryRow(ctx,
		`INSERT INTO assets (project_id, identity, asset_type, discovery_source)
		 VALUES ($1, '192.0.2.51', 'ipv4', 'manual') RETURNING id`, project).Scan(&bare); err != nil {
		t.Fatalf("insert bare asset: %v", err)
	}
	obs, err := s.LatestObservation(ctx, bare)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if obs != nil {
		t.Fatalf("expected no observation, got %+v", obs)
	}
	view, err := s.View(ctx, bare)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if view.OpenPorts == nil || len(view.OpenPorts) != 0 {
		t.Fatalf("open_ports = %v, want empty slice", view.OpenPorts)
	}

	manual, err := s.Create(ctx, project, CreateInput{Identity: "192.0.2.50"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Creating manually records one 'manual' observation, which is the newest
	// record until a scanner reports something.
	first, err := s.LatestObservation(ctx, manual.ID)
	if err != nil {
		t.Fatalf("latest after create: %v", err)
	}
	if first == nil || first.ObservationType != "manual" || first.Source != "manual" {
		t.Fatalf("create recorded no manual observation: %+v", first)
	}

	if _, _, err := s.UpsertFromScan(ctx, project, session, exec, "nmap", scanObs("192.0.2.50")); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	obs, err = s.LatestObservation(ctx, manual.ID)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if obs == nil || obs.Source != "nmap" || obs.ObservationType != "network" {
		t.Fatalf("observation = %+v", obs)
	}
	view, err = s.View(ctx, manual.ID)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if view.LatestObservation == nil || len(view.LatestObservationRaw) == 0 {
		t.Fatalf("view missing latest observation: %+v", view)
	}
	if len(view.OpenPorts) != 2 {
		t.Fatalf("open_ports = %+v, want the two open ports only", view.OpenPorts)
	}
	if view.OpenPorts[0].Port != 22 || view.OpenPorts[0].Service != "ssh" || view.OpenPorts[0].Protocol != "tcp" {
		t.Fatalf("first open port = %+v", view.OpenPorts[0])
	}
	if view.OpenPorts[1].Port != 80 {
		t.Fatalf("second open port = %+v", view.OpenPorts[1])
	}
	// The embedded JSON exposes the same summary.
	raw, _ := json.Marshal(view)
	if !strings.Contains(string(raw), `"open_ports"`) || !strings.Contains(string(raw), `"latest_observation"`) {
		t.Fatalf("view JSON lacks the current view fields: %s", raw)
	}
}

func TestHistoryAndProjectObservations(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")
	session := itest.NewScanSession(t, project)
	exec := itest.NewExecution(t, session, "nmap")

	a1, _, err := s.UpsertFromScan(ctx, project, session, exec, "nmap", scanObs("192.0.2.1"))
	if err != nil {
		t.Fatalf("upsert a1: %v", err)
	}
	if _, _, err := s.UpsertFromScan(ctx, project, session, exec, "nmap", scanObs("192.0.2.1")); err != nil {
		t.Fatalf("upsert a1 again: %v", err)
	}
	a2, _, err := s.UpsertFromScan(ctx, project, session, exec, "nmap", scanObs("192.0.2.2"))
	if err != nil {
		t.Fatalf("upsert a2: %v", err)
	}
	// A manual observation on the second asset, so the history mixes sources.
	if _, err := s.Update(ctx, a2.ID, UpdateInput{Description: strPtr("noted")}); err != nil {
		t.Fatalf("update a2: %v", err)
	}

	hist, err := s.History(ctx, a1.ID, 10, "")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("history length = %d, want 2", len(hist))
	}
	if !hist[0].ObservedAt.After(hist[1].ObservedAt) && !hist[0].ObservedAt.Equal(hist[1].ObservedAt) {
		t.Fatalf("history not newest first: %v then %v", hist[0].ObservedAt, hist[1].ObservedAt)
	}
	filtered, err := s.History(ctx, a1.ID, 10, "manual")
	if err != nil {
		t.Fatalf("filtered history: %v", err)
	}
	if len(filtered) != 0 {
		t.Fatalf("network asset has manual observations: %v", filtered)
	}
	if _, err := s.History(ctx, a1.ID, 10, "nonsense"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad type err = %v", err)
	}
	if _, err := s.History(ctx, uuid.New(), 10, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown asset history err = %v", err)
	}

	recent, err := s.RecentObservations(ctx, project, 50, "", nil)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	// a1 has two scan observations, a2 one scan plus the manual edit.
	if len(recent) != 4 {
		t.Fatalf("project observations = %d, want 4 (3 scan + 1 manual)", len(recent))
	}
	if recent[0].AssetIdentity == "" || recent[0].AssetType == "" {
		t.Fatalf("project observation lacks asset context: %+v", recent[0])
	}
	onlyA2, err := s.RecentObservations(ctx, project, 50, "", &a2.ID)
	if err != nil {
		t.Fatalf("recent filtered: %v", err)
	}
	if len(onlyA2) != 2 {
		t.Fatalf("filtered to a2 = %d, want 2", len(onlyA2))
	}
	limited, err := s.RecentObservations(ctx, project, 1, "", nil)
	if err != nil {
		t.Fatalf("recent limited: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limit ignored: %d", len(limited))
	}
	// Another project's observations never leak in.
	other := itest.NewProject(t, "")
	if _, _, err := s.UpsertFromScan(ctx, other, uuid.Nil, uuid.Nil, "nmap", scanObs("192.0.2.99")); err != nil {
		t.Fatalf("upsert other: %v", err)
	}
	foreign, err := s.RecentObservations(ctx, other, 50, "", nil)
	if err != nil {
		t.Fatalf("recent other: %v", err)
	}
	if len(foreign) != 1 || foreign[0].AssetIdentity != "192.0.2.99" {
		t.Fatalf("cross-project leak: %+v", foreign)
	}
}

func TestAssetListFilters(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")
	if _, err := s.Create(ctx, project, CreateInput{Identity: "192.0.2.10", Description: "jump host", Tags: []string{"edge"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, project, CreateInput{Identity: "db.internal.example", Description: "postgres", AssetType: models.AssetTypeServer}); err != nil {
		t.Fatal(err)
	}
	offline, err := s.Create(ctx, project, CreateInput{Identity: "192.0.2.11", Status: "inactive"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, offline.ID, UpdateInput{Status: strPtr("retired")}); err != nil {
		t.Fatal(err)
	}

	all, total, err := s.List(ctx, project, ListFilters{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 || total != 3 {
		t.Fatalf("list = %d/%d, want 3/3", len(all), total)
	}
	byQuery, _, err := s.List(ctx, project, ListFilters{Query: "jump"})
	if err != nil || len(byQuery) != 1 {
		t.Fatalf("query filter = %d (%v)", len(byQuery), err)
	}
	byTag, _, err := s.List(ctx, project, ListFilters{Query: "edge"})
	if err != nil || len(byTag) != 1 {
		t.Fatalf("tag filter = %d (%v)", len(byTag), err)
	}
	byType, _, err := s.List(ctx, project, ListFilters{Type: models.AssetTypeServer})
	if err != nil || len(byType) != 1 {
		t.Fatalf("type filter = %d (%v)", len(byType), err)
	}
	byStatus, _, err := s.List(ctx, project, ListFilters{Status: "retired"})
	if err != nil || len(byStatus) != 1 {
		t.Fatalf("status filter = %d (%v)", len(byStatus), err)
	}
	if _, _, err := s.List(ctx, project, ListFilters{Status: "nope"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad status err = %v", err)
	}
	if _, _, err := s.List(ctx, project, ListFilters{Sort: "drop_me"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad sort err = %v", err)
	}
	page, total, err := s.List(ctx, project, ListFilters{Limit: 2, Sort: "identity"})
	if err != nil || len(page) != 2 || total != 3 {
		t.Fatalf("pagination = %d/%d (%v)", len(page), total, err)
	}
}

func TestAssetsHTTPSurface(t *testing.T) {
	s := NewService(itest.DB())
	r := chi.NewRouter()
	s.Register(r)
	project := itest.NewProject(t, "")

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	rec := do("POST", "/projects/"+project.String()+"/assets", `{"identity":"203.0.113.5","tags":["web"],"description":"portal"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body = %s", rec.Code, rec.Body)
	}
	var view map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	assetID := view["id"].(string)
	if _, ok := view["open_ports"]; !ok {
		t.Fatalf("create response lacks open_ports: %s", rec.Body)
	}

	if rec := do("POST", "/projects/"+project.String()+"/assets", `{"identity":"203.0.113.5"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate code = %d, want 409", rec.Code)
	}
	if rec := do("POST", "/projects/"+project.String()+"/assets", `{"identity":"!!!"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad identity code = %d, want 400", rec.Code)
	}
	// The identity is immutable: the request schema has no such field.
	if rec := do("PUT", "/assets/"+assetID, `{"identity":"203.0.113.6"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("identity in PUT body code = %d, want 400", rec.Code)
	}
	if rec := do("PUT", "/assets/"+assetID, `{"description":"updated","tags":["web","api"]}`); rec.Code != http.StatusOK {
		t.Fatalf("update code = %d body = %s", rec.Code, rec.Body)
	}
	if rec := do("GET", "/assets/"+assetID, ""); rec.Code != http.StatusOK {
		t.Fatalf("get code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"open_ports"`) {
		t.Fatalf("get body lacks current view: %s", rec.Body)
	}
	if rec := do("GET", "/assets/"+uuid.NewString(), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing get code = %d", rec.Code)
	}
	if rec := do("GET", "/projects/"+project.String()+"/assets?limit=1", ""); rec.Code != http.StatusOK {
		t.Fatalf("list code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("list body = %s", rec.Body)
	}
	if rec := do("GET", "/assets/"+assetID+"/history", ""); rec.Code != http.StatusOK {
		t.Fatalf("history code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"created"`) {
		t.Fatalf("history body = %s", rec.Body)
	}
	if rec := do("GET", "/projects/"+project.String()+"/observations?type=manual", ""); rec.Code != http.StatusOK {
		t.Fatalf("observations code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), "203.0.113.5") {
		t.Fatalf("observations body = %s", rec.Body)
	}
	if rec := do("DELETE", "/assets/"+assetID, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete code = %d", rec.Code)
	}
	if rec := do("DELETE", "/assets/"+assetID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("double delete code = %d", rec.Code)
	}
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }
