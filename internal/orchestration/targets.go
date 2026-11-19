package orchestration

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/scanners"
)

// MaxHostsPerCIDR caps CIDR expansion. Larger prefixes are rejected rather
// than silently scanning thousands of hosts.
const MaxHostsPerCIDR = 1024

// DefaultResolveTimeout bounds DNS lookups during target normalization.
const DefaultResolveTimeout = 5 * time.Second

// hostnameRe accepts RFC-1123 hostnames/FQDNs, with an optional :port
// suffix and IPv6 literals in brackets.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`)

// TargetAuthorizer validates a session target against the project scope
// allowlist. Implemented by the targets module (agent 3); the orchestrator
// only consumes it. A returned error means DENY.
type TargetAuthorizer interface {
	Authorize(ctx context.Context, projectID uuid.UUID, target string) error
}

// NormalizedTarget is one raw session target after validation, CIDR
// expansion and DNS resolution.
type NormalizedTarget struct {
	Raw         string   // as configured
	ResolvedIPs []string // DNS answers recorded for auditability (log only)
	ExecTargets []scanners.Target
	Err         string // non-empty means the target is rejected/denied
}

// TargetNormalizer validates, expands and resolves scan targets.
type TargetNormalizer struct {
	// Resolver is used for hostname lookups; nil uses net.DefaultResolver.
	Resolver *net.Resolver
	// ResolveTimeout bounds a single lookup. Zero uses DefaultResolveTimeout.
	ResolveTimeout time.Duration
	// MaxHostsPerCIDR caps CIDR expansion. Zero uses MaxHostsPerCIDR.
	MaxHostsPerCIDR int
}

// Normalize processes one raw target. It never panics; every rejection is
// reported via NormalizedTarget.Err.
func (n *TargetNormalizer) Normalize(ctx context.Context, projectID uuid.UUID, raw string) NormalizedTarget {
	res := NormalizedTarget{Raw: raw}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		res.Err = "empty target"
		return res
	}

	switch {
	case strings.Contains(raw, "://"):
		t, err := classifyURL(projectID, raw)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		res.ExecTargets = []scanners.Target{t}
		// Best-effort resolution for auditability; a URL target whose host
		// does not currently resolve stays valid (web scanners may still
		// probe it, and DNS may recover).
		n.bestEffortResolveInto(ctx, &res, []string{urlHostname(raw)})
		return res

	case strings.Contains(raw, "/"):
		targets, err := expandCIDR(projectID, raw)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		res.ExecTargets = targets
		for _, t := range targets {
			res.ResolvedIPs = append(res.ResolvedIPs, t.Raw)
		}
		return res

	default:
		t, err := classifyHost(projectID, raw)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		if t.Type == "hostname" || t.Type == "domain" {
			n.resolveInto(ctx, &res, []string{hostOnly(t.Raw)})
			if res.Err != "" {
				return res
			}
		}
		res.ExecTargets = []scanners.Target{t}
		return res
	}
}

func (n *TargetNormalizer) resolveInto(ctx context.Context, res *NormalizedTarget, hosts []string) {
	timeout := n.ResolveTimeout
	if timeout <= 0 {
		timeout = DefaultResolveTimeout
	}
	resolver := n.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, h := range hosts {
		addrs, err := resolver.LookupHost(resolveCtx, h)
		if err != nil {
			res.Err = fmt.Sprintf("hostname %q does not resolve: %v", h, err)
			return
		}
		res.ResolvedIPs = append(res.ResolvedIPs, addrs...)
	}
}

// bestEffortResolveInto records resolved IPs without failing the target.
func (n *TargetNormalizer) bestEffortResolveInto(ctx context.Context, res *NormalizedTarget, hosts []string) {
	mark := *res
	n.resolveInto(ctx, &mark, hosts)
	if mark.Err == "" {
		res.ResolvedIPs = mark.ResolvedIPs
	}
}

func urlHostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}

func classifyURL(projectID uuid.UUID, raw string) (scanners.Target, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return scanners.Target{}, fmt.Errorf("malformed URL target %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return scanners.Target{}, fmt.Errorf("URL target %q has unsupported scheme %q", raw, u.Scheme)
	}
	return scanners.Target{Raw: raw, Type: "url", ProjectID: projectID}, nil
}

func classifyHost(projectID uuid.UUID, raw string) (scanners.Target, error) {
	if strings.HasPrefix(raw, "[") { // bracketed IPv6
		stripped := strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
		if !strings.Contains(stripped, ":") {
			return scanners.Target{}, fmt.Errorf("malformed bracketed IPv6 target %q", raw)
		}
		raw = stripped
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		t := scanners.Target{Raw: raw, ProjectID: projectID}
		if addr.Is4() || addr.Is4In6() {
			t.Type = "ip"
		} else {
			t.Type = "ipv6"
		}
		return t, nil
	}
	if !hostnameRe.MatchString(raw) {
		return scanners.Target{}, fmt.Errorf("malformed target %q", raw)
	}
	t := scanners.Target{Raw: raw, ProjectID: projectID}
	if strings.Contains(hostOnly(raw), ".") {
		t.Type = "domain"
	} else {
		t.Type = "hostname"
	}
	return t, nil
}

func hostOnly(s string) string {
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], ":") {
		// single colon: strip :port (never present for bare IPv6, which has many)
		return s[:i]
	}
	return s
}

// expandCIDR expands an IPv4/IPv6 prefix, capped at MaxHostsPerCIDR.
func expandCIDR(projectID uuid.UUID, cidr string) ([]scanners.Target, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("malformed CIDR %q: %v", cidr, err)
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	is4 := addr.Is4() || addr.Is4In6()
	bits := 128
	if is4 {
		bits = 32
	}
	hostBits := bits - prefix.Bits()
	if hostBits < 0 {
		return nil, fmt.Errorf("malformed CIDR %q", cidr)
	}
	if hostBits >= 31 {
		return nil, fmt.Errorf("CIDR %q far exceeds the %d-host cap", cidr, MaxHostsPerCIDR)
	}
	count := uint64(1) << hostBits
	if count > uint64(MaxHostsPerCIDR) {
		return nil, fmt.Errorf("CIDR %q expands to %d hosts, above the %d-host cap", cidr, count, MaxHostsPerCIDR)
	}
	out := make([]scanners.Target, 0, count)
	cur := addr
	for i := uint64(0); i < count; i++ {
		out = append(out, scanners.Target{Raw: cur.String(), Type: targetTypeFor(cur), ProjectID: projectID})
		cur = cur.Next()
	}
	return out, nil
}

func targetTypeFor(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "ip"
	}
	return "ipv6"
}
