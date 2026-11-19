package reports

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleZipItems() []zipFinding {
	return []zipFinding{
		{Seq: 2, Title: "SQL Injection in login form, quoted", Severity: "critical",
			Asset: "10.0.0.5", Fingerprint: "fp-b", PDF: []byte("%PDF-1.4 fake two")},
		{Seq: 1, Title: "Outdated TLS", Severity: "medium",
			Asset: "juice.lab", Fingerprint: "fp-a", PDF: []byte("%PDF-1.4 fake one")},
		{Seq: 3, Title: "Outdated TLS", Severity: "low",
			Asset: "web.lab", Fingerprint: "fp-c", PDF: []byte("%PDF-1.4 fake three")},
	}
}

func TestBuildZipStructure(t *testing.T) {
	data, err := buildZip(sampleZipItems())
	require.NoError(t, err)
	require.Greater(t, len(data), 100)

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)

	names := make([]string, 0, len(zr.File))
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	// Deterministic ordering by sequence, slugified titles, duplicate
	// collision gets a numeric suffix.
	assert.Equal(t, []string{
		"findings/FND-1-outdated-tls.pdf",
		"findings/FND-2-sql-injection-in-login-form-quoted.pdf",
		"findings/FND-3-outdated-tls.pdf", // distinct sequence ⇒ distinct name
		"manifest.csv",
	}, names)

	// PDF payloads round-trip verbatim.
	for _, f := range zr.File {
		if f.Name == "manifest.csv" {
			continue
		}
		rc, err := f.Open()
		require.NoError(t, err)
		b, err := io.ReadAll(rc)
		rc.Close()
		require.NoError(t, err)
		assert.Contains(t, string(b), "%PDF-1.4 fake")
	}
}

func TestBuildZipManifest(t *testing.T) {
	data, err := buildZip(sampleZipItems())
	require.NoError(t, err)

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)

	var mf *zip.File
	for _, f := range zr.File {
		if f.Name == "manifest.csv" {
			mf = f
		}
	}
	require.NotNil(t, mf, "manifest.csv must be present")
	rc, err := mf.Open()
	require.NoError(t, err)
	defer rc.Close()
	records, err := csv.NewReader(rc).ReadAll()
	require.NoError(t, err)

	require.Equal(t, []string{"finding_id", "title", "severity", "asset", "fingerprint"}, records[0])
	require.Len(t, records, 4)
	// Rows sorted by sequence number.
	assert.Equal(t, []string{"FND-1", "Outdated TLS", "medium", "juice.lab", "fp-a"}, records[1])
	assert.Equal(t, []string{"FND-2", "SQL Injection in login form, quoted", "critical", "10.0.0.5", "fp-b"}, records[2],
		"comma in title must survive CSV round-trip")
	assert.Equal(t, []string{"FND-3", "Outdated TLS", "low", "web.lab", "fp-c"}, records[3])
}

func TestBuildZipEmptyAndCollision(t *testing.T) {
	// Empty archive still contains the manifest header.
	data, err := buildZip(nil)
	require.NoError(t, err)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	require.Len(t, zr.File, 1)
	rc, _ := zr.File[0].Open()
	b, _ := io.ReadAll(rc)
	rc.Close()
	assert.Equal(t, "finding_id,title,severity,asset,fingerprint\n", string(b))

	// Two findings sharing a sequence and title collide on entry name; the
	// second must be uniquified, not overwritten.
	dupes := []zipFinding{
		{Seq: 7, Title: "Same Title", Severity: "low", Asset: "a", Fingerprint: "1", PDF: []byte("one")},
		{Seq: 7, Title: "Same Title", Severity: "low", Asset: "b", Fingerprint: "2", PDF: []byte("two")},
	}
	data, err = buildZip(dupes)
	require.NoError(t, err)
	zr, err = zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, f := range zr.File {
		require.False(t, seen[f.Name], "duplicate entry %s", f.Name)
		seen[f.Name] = true
	}
	assert.True(t, seen["findings/FND-7-same-title.pdf"])
	assert.True(t, seen["findings/FND-7-same-title-2.pdf"])
}
