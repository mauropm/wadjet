package orchestration

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeTargets(t *testing.T) {
	pid := uuid.New()
	n := &TargetNormalizer{}
	ctx := context.Background()

	tests := []struct {
		name    string
		raw     string
		wantErr string
		types   []string // ExecTargets types
		nCount  int      // expected number of exec targets
	}{
		{name: "ipv4", raw: "10.0.0.7", types: []string{"ip"}, nCount: 1},
		{name: "ipv6", raw: "2001:db8::1", types: []string{"ipv6"}, nCount: 1},
		{name: "bracketed ipv6", raw: "[2001:db8::1]", types: []string{"ipv6"}, nCount: 1},
		{name: "hostname", raw: "localhost", types: []string{"hostname"}, nCount: 1},
		{name: "fqdn", raw: "www.example.com", types: []string{"domain"}, nCount: 1},
		{name: "fqdn with port", raw: "www.example.com:8443", types: []string{"domain"}, nCount: 1},
		{name: "cidr /30", raw: "192.0.2.0/30", types: []string{"ip", "ip", "ip", "ip"}, nCount: 4},
		{name: "cidr /32 single", raw: "192.0.2.5/32", types: []string{"ip"}, nCount: 1},
		{name: "cidr /22 at cap", raw: "198.51.100.0/22", types: nil, nCount: 1024},
		{name: "cidr above cap rejected", raw: "10.0.0.0/20", wantErr: "above the 1024-host cap"},
		{name: "huge ipv6 cidr rejected", raw: "2001:db8::/64", wantErr: "exceeds the"},
		{name: "url ok", raw: "https://app.example.com/path", types: []string{"url"}, nCount: 1},
		{name: "url bad scheme", raw: "ftp://x.example.com", wantErr: "unsupported scheme"},
		{name: "url malformed", raw: "http://%zz", wantErr: "malformed"},
		{name: "empty", raw: "   ", wantErr: "empty target"},
		{name: "shell injection", raw: "10.0.0.1; rm -rf /", wantErr: "malformed"},
		{name: "space", raw: "10.0.0.1 10.0.0.2", wantErr: "malformed"},
		{name: "flag", raw: "--script=all", wantErr: "malformed"},
		{name: "malformed cidr", raw: "10.0.0.0/33", wantErr: "malformed CIDR"},
		{name: "traversal", raw: "../../../etc/passwd", wantErr: "malformed"},
		{name: "unicode homoglyph-ish", raw: "10.0.0.а", wantErr: "malformed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := n.Normalize(ctx, pid, tc.raw)
			if tc.wantErr != "" {
				require.NotEmpty(t, res.Err)
				assert.Contains(t, res.Err, tc.wantErr)
				assert.Empty(t, res.ExecTargets)
				return
			}
			require.Empty(t, res.Err)
			require.Len(t, res.ExecTargets, tc.nCount)
			for i, wantType := range tc.types {
				assert.Equal(t, wantType, res.ExecTargets[i].Type)
				assert.Equal(t, pid, res.ExecTargets[i].ProjectID)
			}
		})
	}
}

func TestNormalizeHostnameResolution(t *testing.T) {
	n := &TargetNormalizer{}
	res := n.Normalize(context.Background(), uuid.New(), "localhost")
	require.Empty(t, res.Err, "localhost must resolve")
	assert.NotEmpty(t, res.ResolvedIPs, "resolved IPs recorded")
	require.Len(t, res.ExecTargets, 1)
	assert.Equal(t, "localhost", res.ExecTargets[0].Raw, "scanner receives the original hostname")
}

func TestNormalizeUnresolvableHostname(t *testing.T) {
	n := &TargetNormalizer{}
	res := n.Normalize(context.Background(), uuid.New(), "definitely-not-a-host.wadjet.invalid")
	assert.NotEmpty(t, res.Err)
	assert.Contains(t, strings.ToLower(res.Err), "resolve")
}

func TestExpandCIDRBoundaries(t *testing.T) {
	// /23 = 512 ok, /22 = 1024 ok (cap inclusive), /21 = 2048 rejected.
	_, err := expandCIDR(uuid.New(), "192.0.2.0/23")
	require.NoError(t, err)
	got, err := expandCIDR(uuid.New(), "192.0.2.0/22")
	require.NoError(t, err)
	assert.Len(t, got, 1024)
	assert.Equal(t, "192.0.0.0", got[0].Raw, "masked to network address")
	assert.Equal(t, "192.0.0.255", got[255].Raw)
	_, err = expandCIDR(uuid.New(), "192.0.0.0/21")
	require.Error(t, err)

	// /126 = 4 ipv6 hosts
	got, err = expandCIDR(uuid.New(), "2001:db8::/126")
	require.NoError(t, err)
	require.Len(t, got, 4)
	assert.Equal(t, "2001:db8::", got[0].Raw)
	assert.Equal(t, "ipv6", got[0].Type)
}
