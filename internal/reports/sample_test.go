package reports

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWriteSamples is a gated helper (not part of the normal suite): run
// with WADJET_SAMPLE_DIR set to persist one of every deliverable type for
// visual inspection:
//
//	WADJET_SAMPLE_DIR=/tmp/wadjet-sample go test ./internal/reports/ -run TestWriteSamples
func TestWriteSamples(t *testing.T) {
	dir := os.Getenv("WADJET_SAMPLE_DIR")
	if dir == "" {
		t.Skip("set WADJET_SAMPLE_DIR to emit sample deliverables")
	}
	e := setup(t)
	h := e.router()

	type job struct {
		name, method, path, body string
	}
	jobs := []job{
		{"scan-report", "POST", "/projects/" + e.project.String() + "/reports/scan",
			`{"session_id":"` + e.session.String() + `"}`},
		{"findings-zip", "POST", "/projects/" + e.project.String() + "/reports/findings",
			`{"consolidated":false}`},
		{"findings-consolidated", "POST", "/projects/" + e.project.String() + "/reports/findings",
			`{"consolidated":true}`},
		{"finding-advisory", "POST", "/findings/" + e.f1.String() + "/report", `{}`},
	}
	for _, j := range jobs {
		rec := do(t, h, j.method, j.path, j.body)
		rpt := decodeReport(t, rec)
		done := waitReport(t, e.db, rpt.ID)
		blob, err := os.ReadFile(filepath.Join(e.dir, filepath.FromSlash(done.FilePath)))
		require.NoError(t, err)
		out := filepath.Join(dir, j.name+filepath.Ext(done.FilePath))
		require.NoError(t, os.WriteFile(out, blob, 0o644))
		t.Logf("sample: %s (%d bytes)", out, len(blob))
		if filepath.Ext(out) == ".pdf" {
			assert.True(t, len(blob) > 1000)
		}
	}
}
