package registry

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/database"
)

const testDatabaseURL = "postgres://wadjet:wadjet@127.0.0.1:5432/wadjet"

func openTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), testDatabaseURL)
	require.NoError(t, err, "test database must be running")
	t.Cleanup(db.Close)
	require.NoError(t, database.Migrate(context.Background(), db))
	return db
}

func writeManifestDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	return dir
}

func probeManifest(name, executable, adapter, parser string) string {
	if adapter == "native" {
		return `name: ` + name + `
display_name: Probe ` + name + `
adapter: native
enabled: true
asset_types: [ip]
capabilities: [port_discovery]
output: {format: none, parser: ` + parser + `}
configuration: {timeout: 30}
`
	}
	return `name: ` + name + `
display_name: Probe ` + name + `
executable: ` + executable + `
adapter: command
enabled: true
asset_types: [ip]
capabilities: [port_discovery]
output: {format: text, parser: ` + parser + `}
configuration: {timeout: 30}
`
}

func TestRegistryLoadListEnableDisable(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	dir := writeManifestDir(t, map[string]string{
		"probe-ok.yaml":  probeManifest("reg-probe-ok", "/bin/echo", "command", "none"),
		"probe-bad.yaml": probeManifest("reg-probe-bad", "wadjet-no-such-tool", "command", "none"),
	})

	reg := New(db)
	require.NoError(t, reg.Load(ctx, dir))

	// status derived from executable lookup
	if _, err := exec.LookPath("nmap"); err == nil {
		t.Log("nmap present on this machine")
	}
	recOK, err := reg.GetRecord(ctx, "reg-probe-ok")
	require.NoError(t, err)
	assert.Equal(t, StatusAvailable, recOK.Status)
	assert.Equal(t, "command", recOK.Adapter)
	assert.True(t, recOK.Enabled)

	recBad, err := reg.GetRecord(ctx, "reg-probe-bad")
	require.NoError(t, err)
	assert.Equal(t, StatusMissing, recBad.Status)
	assert.Contains(t, recBad.StatusDetail, "not found in PATH")

	// manifest stored as JSONB with snake_case keys
	var m map[string]any
	require.NoError(t, json.Unmarshal(recOK.Manifest, &m))
	assert.Equal(t, "reg-probe-ok", m["name"])
	assert.Equal(t, "command", m["adapter"])

	// registry Get honours enabled + availability
	_, ok := reg.Get("reg-probe-ok")
	assert.True(t, ok)
	_, ok = reg.Get("reg-probe-bad")
	assert.False(t, ok, "missing executable must not be executable")

	require.NoError(t, reg.Disable(ctx, "reg-probe-ok"))
	_, ok = reg.Get("reg-probe-ok")
	assert.False(t, ok, "disabled scanner must not be executable")
	assert.True(t, reg.Enabled("reg-probe-ok") == false)
	recOK, _ = reg.GetRecord(ctx, "reg-probe-ok")
	assert.False(t, recOK.Enabled)
	assert.Equal(t, StatusDisabled, recOK.Status)

	require.NoError(t, reg.Enable(ctx, "reg-probe-ok"))
	_, ok = reg.Get("reg-probe-ok")
	assert.True(t, ok)

	// unknown scanner
	require.Error(t, reg.Enable(ctx, "reg-ghost"))

	// List is persisted and sorted (scoped to this test's scanners; the
	// table is shared across the test suite).
	list, err := reg.List(ctx)
	require.NoError(t, err)
	var names []string
	for _, r := range list {
		if strings.HasPrefix(r.Name, "reg-probe-") {
			names = append(names, r.Name)
		}
	}
	assert.Equal(t, []string{"reg-probe-bad", "reg-probe-ok"}, names)

	// GetRecord by uuid also works
	rec, err := reg.GetRecord(ctx, recOK.ID.String())
	require.NoError(t, err)
	assert.Equal(t, "reg-probe-ok", rec.Name)
}

func TestRegistryReloadKeepsDisabledState(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	dir := writeManifestDir(t, map[string]string{
		"p.yaml": probeManifest("reg-reload", "/bin/echo", "command", "none"),
	})
	reg := New(db)
	require.NoError(t, reg.Load(ctx, dir))
	require.NoError(t, reg.Disable(ctx, "reg-reload"))

	// Simulate server restart: new registry loads the same dir.
	reg2 := New(db)
	require.NoError(t, reg2.Load(ctx, dir))
	assert.False(t, reg2.Enabled("reg-reload"), "reloading manifests must not silently re-enable scanners")
}

func TestRegistryCheckAvailability(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	dir := writeManifestDir(t, map[string]string{
		"ok.yaml":  probeManifest("reg-avail-ok", "/bin/echo", "command", "none"),
		"bad.yaml": probeManifest("reg-avail-bad", "definitely-missing-binary", "command", "none"),
	})
	reg := New(db)
	require.NoError(t, reg.Load(ctx, dir))

	rec, err := reg.CheckAvailability(ctx, "reg-avail-ok")
	require.NoError(t, err)
	assert.Equal(t, StatusAvailable, rec.Status)
	assert.NotNil(t, rec.LastChecked)

	rec, err = reg.CheckAvailability(ctx, "reg-avail-bad")
	require.NoError(t, err)
	assert.Equal(t, StatusMissing, rec.Status)

	_, err = reg.CheckAvailability(ctx, "reg-ghost")
	require.Error(t, err)
}

func TestRegistryLoadsBundledManifests(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	reg := New(db)
	require.NoError(t, reg.Load(ctx, filepath.Join("..", "..", "..", "configs", "scanners")))

	for _, name := range []string{"nmap", "nuclei", "nativeprobe"} {
		rec, err := reg.GetRecord(ctx, name)
		require.NoError(t, err, name)
		assert.NotEmpty(t, rec.DisplayName)
	}
	rec, err := reg.GetRecord(ctx, "nuclei")
	require.NoError(t, err)
	assert.False(t, rec.Enabled, "nuclei ships disabled")

	// nmap is a real implementation
	if _, ok := reg.Lookup("nmap"); !ok {
		t.Fatal("nmap implementation missing")
	}
	_, ok := reg.Get("nativeprobe")
	assert.True(t, ok, "nativeprobe is native and always available")
}

func TestRegistryRejectsUnknownParser(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	dir := writeManifestDir(t, map[string]string{
		"x.yaml": probeManifest("reg-unknown-parser", "/bin/echo", "command", "quantum_parser"),
	})
	reg := New(db)
	err := reg.Load(ctx, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output.parser")
}
