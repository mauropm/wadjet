package projects

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/assets/itest"
	"github.com/mauropm/wadjet/internal/models"
)

// seedOriginal builds a fully populated project: tags, settings with
// report_prefs, included/excluded targets, scanner configurations and two
// profiles with scanner bindings, plus historical rows (session, asset,
// finding, observations) that must never be cloned.
type seed struct {
	projectID  uuid.UUID
	scanners   []uuid.UUID
	targets    []string
	profileIDs []uuid.UUID
	sessionID  uuid.UUID
	assetID    uuid.UUID
	findingID  uuid.UUID
}

func seedOriginal(t *testing.T, s *Service) *seed {
	t.Helper()
	ctx := context.Background()
	name := uniqueName(t, "origin")
	p := mustCreate(t, s, name)
	if _, err := s.Update(ctx, p.ID, UpdateInput{
		Description: strPtr("original description"),
		Tags:        &[]string{"external", "prod"},
		Settings:    json.RawMessage(`{"aggressiveness":"fast","report_prefs":{"include_evidence":true,"language":"en"}}`),
	}); err != nil {
		t.Fatalf("seed update: %v", err)
	}

	scanners := []uuid.UUID{itest.NewScanner(t, ""), itest.NewScanner(t, "")}
	for i, sc := range scanners {
		itest.MustExec(t,
			`INSERT INTO scanner_configurations (project_id, scanner_id, config, updated_at)
			 VALUES ($1, $2, $3::jsonb, now())`, p.ID, sc, fmt.Sprintf(`{"profile":"%d"}`, i))
	}

	targets := []string{"10.10.0.0/24", "www.example.com", "10.10.0.9"}
	itest.MustExec(t,
		`INSERT INTO project_targets (project_id, target, target_type, excluded, note) VALUES ($1,$2,'cidr',false,'')`,
		p.ID, targets[0])
	itest.MustExec(t,
		`INSERT INTO project_targets (project_id, target, target_type, excluded, note) VALUES ($1,$2,'hostname',false,'web')`,
		p.ID, targets[1])
	itest.MustExec(t,
		`INSERT INTO project_targets (project_id, target, target_type, excluded, note) VALUES ($1,$2,'ip',true,'out of scope')`,
		p.ID, targets[2])

	var fast, full uuid.UUID
	if err := itest.DB().QueryRow(ctx,
		`INSERT INTO scan_profiles (project_id, name, description, target_selection, excluded_targets, timeout_seconds, report_prefs)
		 VALUES ($1, 'fast', 'quick sweep', ARRAY['10.10.0.0/24'], ARRAY['10.10.0.9'], 600, '{"format":"pdf"}'::jsonb) RETURNING id`,
		p.ID).Scan(&fast); err != nil {
		t.Fatalf("seed profile fast: %v", err)
	}
	if err := itest.DB().QueryRow(ctx,
		`INSERT INTO scan_profiles (project_id, name, description, target_selection, excluded_targets, timeout_seconds, report_prefs)
		 VALUES ($1, 'full', 'deep scan', '{}', '{}', 3600, '{}'::jsonb) RETURNING id`,
		p.ID).Scan(&full); err != nil {
		t.Fatalf("seed profile full: %v", err)
	}
	itest.MustExec(t, `INSERT INTO scan_profile_scanners (profile_id, scanner_id, config, sort_order) VALUES ($1,$2,'{"safe":true}'::jsonb, 0)`, fast, scanners[0])
	itest.MustExec(t, `INSERT INTO scan_profile_scanners (profile_id, scanner_id, config, sort_order) VALUES ($1,$2,'{}'::jsonb, 1)`, full, scanners[1])

	// Historical data: must never be cloned.
	session := itest.NewScanSession(t, p.ID)
	exec := itest.NewExecution(t, session, "nmap")
	var asset uuid.UUID
	if err := itest.DB().QueryRow(ctx,
		`INSERT INTO assets (project_id, identity, asset_type, discovery_source) VALUES ($1, '10.10.0.1', 'ipv4', 'scanner') RETURNING id`,
		p.ID).Scan(&asset); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	itest.MustExec(t,
		`INSERT INTO asset_observations (asset_id, scan_session_id, scanner_execution_id, observation_type, raw, source)
		 VALUES ($1,$2,$3,'network','{"ports":[{"port":22}]}','nmap')`, asset, session, exec)
	var finding uuid.UUID
	if err := itest.DB().QueryRow(ctx,
		`INSERT INTO findings (project_id, asset_id, title, scanner, fingerprint, severity, status)
		 VALUES ($1,$2,'Old finding','nmap','fpold','high','open') RETURNING id`,
		p.ID, asset).Scan(&finding); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	itest.MustExec(t,
		`INSERT INTO finding_observations (finding_id, scan_session_id, scanner_execution_id, status_at_detection, raw)
		 VALUES ($1,$2,$3,'open','{}')`, finding, session, exec)
	itest.MustExec(t,
		`INSERT INTO finding_status_history (finding_id, from_status, to_status, note) VALUES ($1,'','open','created')`, finding)

	return &seed{projectID: p.ID, scanners: scanners, targets: targets,
		profileIDs: []uuid.UUID{fast, full}, sessionID: session, assetID: asset, findingID: finding}
}

func TestCloneFullCopiesConfigurationOnly(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	src := seedOriginal(t, s)

	clone, err := s.Clone(ctx, src.projectID, CloneInput{Copy: DefaultCopyOptions()}, nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	itest.CleanupProject(t, clone.ID)

	if clone.ID == src.projectID {
		t.Fatal("clone reused the source project id")
	}
	if want := mustGet(t, s, src.projectID).Name + " (Clone)"; clone.Name != want {
		t.Fatalf("default clone name = %q, want %q", clone.Name, want)
	}
	if clone.Status != "active" {
		t.Fatalf("clone status = %q, want active", clone.Status)
	}
	if clone.Description != "original description" {
		t.Fatalf("clone description = %q, want inherited", clone.Description)
	}
	if len(clone.Tags) != 2 {
		t.Fatalf("clone tags = %v, want 2 copied", clone.Tags)
	}
	for _, want := range []string{"aggressiveness", "report_prefs"} {
		if !jsonHasKey(t, clone.Settings, want) {
			t.Fatalf("clone settings %s missing %q", clone.Settings, want)
		}
	}

	// Configuration facets are duplicated.
	if n := itest.Count(t, `SELECT count(*) FROM project_targets WHERE project_id=$1`, clone.ID); n != 3 {
		t.Fatalf("cloned targets = %d, want 3", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM project_targets WHERE project_id=$1 AND excluded`, clone.ID); n != 1 {
		t.Fatalf("cloned excluded targets = %d, want 1", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scanner_configurations WHERE project_id=$1`, clone.ID); n != 2 {
		t.Fatalf("cloned scanner configs = %d, want 2", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scan_profiles WHERE project_id=$1`, clone.ID); n != 2 {
		t.Fatalf("cloned profiles = %d, want 2", n)
	}
	if n := itest.Count(t,
		`SELECT count(*) FROM scan_profile_scanners sps
		   JOIN scan_profiles sp ON sp.id = sps.profile_id
		  WHERE sp.project_id = $1`, clone.ID); n != 2 {
		t.Fatalf("cloned profile bindings = %d, want 2", n)
	}

	// Cloned rows have fresh identities: no id may collide with the source.
	for _, q := range []struct {
		name string
		sql  string
		want int
	}{
		{"project_targets", `SELECT id FROM project_targets WHERE project_id = $1`, 3},
		{"scan_profiles", `SELECT id FROM scan_profiles WHERE project_id = $1`, 2},
		{"scan_profile_scanners", `SELECT sps.id FROM scan_profile_scanners sps
		      JOIN scan_profiles sp ON sp.id = sps.profile_id WHERE sp.project_id = $1`, 2},
		{"scanner_configurations", `SELECT id FROM scanner_configurations WHERE project_id = $1`, 2},
	} {
		srcIDs := idSet(t, q.sql, src.projectID)
		cloneIDs := idSet(t, q.sql, clone.ID)
		if len(cloneIDs) != q.want {
			t.Fatalf("%s clone rows = %d, want %d", q.name, len(cloneIDs), q.want)
		}
		for id := range cloneIDs {
			if srcIDs[id] {
				t.Fatalf("%s row %s was shared between source and clone", q.name, id)
			}
		}
	}

	// Historical data is never cloned.
	if n := itest.Count(t, `SELECT count(*) FROM scan_sessions WHERE project_id=$1`, clone.ID); n != 0 {
		t.Fatalf("clone has %d scan sessions, want 0", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM assets WHERE project_id=$1`, clone.ID); n != 0 {
		t.Fatalf("clone has %d assets, want 0", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id=$1`, clone.ID); n != 0 {
		t.Fatalf("clone has %d findings, want 0", n)
	}
	if n := itest.Count(t,
		`SELECT count(*) FROM asset_observations ao JOIN assets a ON a.id = ao.asset_id WHERE a.project_id = $1`,
		clone.ID); n != 0 {
		t.Fatalf("clone has %d asset observations, want 0", n)
	}
	// The source still owns all its history.
	if n := itest.Count(t, `SELECT count(*) FROM scan_sessions WHERE project_id=$1`, src.projectID); n != 1 {
		t.Fatalf("source lost its scan session: %d", n)
	}
}

func TestCloneIndependence(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	src := seedOriginal(t, s)

	clone, err := s.Clone(ctx, src.projectID, CloneInput{Name: "mutated clone", Copy: DefaultCopyOptions()}, nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	itest.CleanupProject(t, clone.ID)

	// Mutate every cloned facet.
	renamed := "clone renamed"
	tags := []string{"clone-only"}
	if _, err := s.Update(ctx, clone.ID, UpdateInput{
		Name: &renamed, Tags: &tags, Settings: json.RawMessage(`{"report_prefs":{"include_evidence":false}}`),
	}); err != nil {
		t.Fatalf("update clone: %v", err)
	}
	itest.MustExec(t, `DELETE FROM project_targets WHERE project_id = $1 AND target = 'www.example.com'`, clone.ID)
	itest.MustExec(t, `INSERT INTO project_targets (project_id, target, target_type, excluded, note) VALUES ($1,'clone.only','hostname',false,'')`, clone.ID)
	itest.MustExec(t, `DELETE FROM scanner_configurations WHERE project_id = $1 AND scanner_id = $2`, clone.ID, src.scanners[0])
	itest.MustExec(t, `UPDATE scan_profiles SET name = 'clone-fast', timeout_seconds = 60 WHERE project_id = $1 AND name = 'fast'`, clone.ID)
	itest.MustExec(t, `UPDATE scan_profile_scanners SET config = '{"aggressive":true}'::jsonb
	                      WHERE profile_id = (SELECT id FROM scan_profiles WHERE project_id = $1 AND name = 'clone-fast')`, clone.ID)

	// The original must be untouched.
	orig, err := s.Get(ctx, src.projectID)
	if err != nil {
		t.Fatalf("get original: %v", err)
	}
	if len(orig.Tags) != 2 || !jsonHasKey(t, orig.Settings, "aggressiveness") {
		t.Fatalf("original project mutated by clone edits: tags=%v settings=%s", orig.Tags, orig.Settings)
	}
	if n := itest.Count(t, `SELECT count(*) FROM project_targets WHERE project_id=$1`, src.projectID); n != 3 {
		t.Fatalf("original targets = %d, want 3", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM project_targets WHERE project_id=$1 AND target='clone.only'`, src.projectID); n != 0 {
		t.Fatalf("clone-only target leaked into the original")
	}
	if n := itest.Count(t, `SELECT count(*) FROM scanner_configurations WHERE project_id=$1`, src.projectID); n != 2 {
		t.Fatalf("original scanner configs = %d, want 2", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scan_profiles WHERE project_id=$1 AND name='fast'`, src.projectID); n != 1 {
		t.Fatalf("original profile was renamed by the clone")
	}
	var cfg string
	if err := itest.DB().QueryRow(ctx,
		`SELECT sps.config::text FROM scan_profile_scanners sps
		   JOIN scan_profiles sp ON sp.id = sps.profile_id
		  WHERE sp.project_id = $1 AND sp.name = 'fast'`, src.projectID).Scan(&cfg); err != nil {
		t.Fatalf("read original binding: %v", err)
	}
	if cfg != `{"safe": true}` {
		t.Fatalf("original binding config = %s, want {\"safe\": true}", cfg)
	}
}

func TestCloneCopyFlagsAreIndependent(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	src := seedOriginal(t, s)

	cases := []struct {
		name           string
		opts           CopyOptions
		wantTargets    int
		wantConfigs    int
		wantProfiles   int
		wantTags       int
		settingsHas    []string
		settingsLacks  []string
		wantProfileCfg int
	}{
		{
			name:          "none",
			opts:          CopyOptions{},
			settingsHas:   nil,
			settingsLacks: []string{"aggressiveness", "report_prefs"},
		},
		{
			name:          "targets only",
			opts:          CopyOptions{Targets: true},
			wantTargets:   3,
			settingsLacks: []string{"aggressiveness", "report_prefs"},
		},
		{
			name:          "scanner configs only",
			opts:          CopyOptions{ScannerConfigs: true},
			wantConfigs:   2,
			settingsLacks: []string{"aggressiveness", "report_prefs"},
		},
		{
			name:           "profiles only keeps empty report prefs",
			opts:           CopyOptions{Profiles: true},
			wantProfiles:   2,
			wantProfileCfg: 2,
			settingsLacks:  []string{"aggressiveness", "report_prefs"},
		},
		{
			name:          "report prefs only",
			opts:          CopyOptions{ReportPrefs: true},
			settingsHas:   []string{"report_prefs"},
			settingsLacks: []string{"aggressiveness"},
		},
		{
			name:        "settings only",
			opts:        CopyOptions{Settings: true},
			settingsHas: []string{"aggressiveness", "report_prefs"},
		},
		{
			name:          "tags only",
			opts:          CopyOptions{Tags: true},
			wantTags:      2,
			settingsLacks: []string{"aggressiveness", "report_prefs"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clone, err := s.Clone(ctx, src.projectID, CloneInput{Copy: tc.opts}, nil)
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			itest.CleanupProject(t, clone.ID)

			if n := itest.Count(t, `SELECT count(*) FROM project_targets WHERE project_id=$1`, clone.ID); n != tc.wantTargets {
				t.Fatalf("targets = %d, want %d", n, tc.wantTargets)
			}
			if n := itest.Count(t, `SELECT count(*) FROM scanner_configurations WHERE project_id=$1`, clone.ID); n != tc.wantConfigs {
				t.Fatalf("scanner configs = %d, want %d", n, tc.wantConfigs)
			}
			if n := itest.Count(t, `SELECT count(*) FROM scan_profiles WHERE project_id=$1`, clone.ID); n != tc.wantProfiles {
				t.Fatalf("profiles = %d, want %d", n, tc.wantProfiles)
			}
			if n := itest.Count(t,
				`SELECT count(*) FROM scan_profile_scanners sps JOIN scan_profiles sp ON sp.id=sps.profile_id WHERE sp.project_id=$1`,
				clone.ID); n != tc.wantProfileCfg {
				t.Fatalf("profile bindings = %d, want %d", n, tc.wantProfileCfg)
			}
			if len(clone.Tags) != tc.wantTags {
				t.Fatalf("tags = %v, want %d entries", clone.Tags, tc.wantTags)
			}
			for _, k := range tc.settingsHas {
				if !jsonHasKey(t, clone.Settings, k) {
					t.Fatalf("settings %s missing %q", clone.Settings, k)
				}
			}
			for _, k := range tc.settingsLacks {
				if jsonHasKey(t, clone.Settings, k) {
					t.Fatalf("settings %s should not contain %q", clone.Settings, k)
				}
			}
			if tc.opts.Profiles && !tc.opts.ReportPrefs {
				var prefs json.RawMessage
				if err := itest.DB().QueryRow(ctx,
					`SELECT report_prefs FROM scan_profiles WHERE project_id=$1 LIMIT 1`, clone.ID).Scan(&prefs); err != nil {
					t.Fatalf("read prefs: %v", err)
				}
				if string(prefs) != "{}" {
					t.Fatalf("copied profile report_prefs = %s, want {}", prefs)
				}
			}
		})
	}
}

func TestCloneOverridesAndMissingSource(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	src := seedOriginal(t, s)

	desc := "explicit"
	clone, err := s.Clone(ctx, src.projectID, CloneInput{Name: "  ", Description: &desc, Copy: DefaultCopyOptions()}, nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	itest.CleanupProject(t, clone.ID)
	if clone.Description != "explicit" {
		t.Fatalf("description override ignored: %q", clone.Description)
	}
	if want := mustGet(t, s, src.projectID).Name + " (Clone)"; clone.Name != want {
		t.Fatalf("blank name should fall back to %q, got %q", want, clone.Name)
	}

	named, err := s.Clone(ctx, src.projectID, CloneInput{Name: "Quarterly retest", Copy: CopyOptions{}}, nil)
	if err != nil {
		t.Fatalf("named clone: %v", err)
	}
	itest.CleanupProject(t, named.ID)
	if named.Name != "Quarterly retest" {
		t.Fatalf("name = %q", named.Name)
	}
	// An empty description override is honoured literally, not inherited.
	blank := ""
	blankClone, err := s.Clone(ctx, src.projectID, CloneInput{Description: &blank, Copy: CopyOptions{}}, nil)
	if err != nil {
		t.Fatalf("blank clone: %v", err)
	}
	itest.CleanupProject(t, blankClone.ID)
	if blankClone.Description != "" {
		t.Fatalf("description = %q, want empty", blankClone.Description)
	}

	if _, err := s.Clone(ctx, uuid.New(), CloneInput{Copy: DefaultCopyOptions()}, nil); err == nil {
		t.Fatal("cloning a missing project should fail")
	}
}

// ───────────────────────────────────────────── helpers

func mustGet(t *testing.T, s *Service, id uuid.UUID) *models.Project {
	t.Helper()
	p, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return p
}

func jsonHasKey(t *testing.T, raw json.RawMessage, key string) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("settings not an object: %v", err)
	}
	_, ok := m[key]
	return ok
}

func idSet(t *testing.T, query string, projectID uuid.UUID) map[uuid.UUID]bool {
	t.Helper()
	rows, err := itest.DB().Query(context.Background(), query, projectID)
	if err != nil {
		t.Fatalf("ids from %s: %v", query, err)
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		out[id] = true
	}
	return out
}
