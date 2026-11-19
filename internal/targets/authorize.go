package targets

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Target kinds. They reuse the vocabulary of project_targets.target_type and
// of scanners.Target.Type so a stored entry can be interpreted without a
// second mapping layer.
const (
	KindIP       = "ip"
	KindIPv6     = "ipv6"
	KindCIDR     = "cidr"
	KindHostname = "hostname"
	KindDomain   = "domain"
	KindURL      = "url"
	KindAuto     = "auto"
)

// ParsedTarget is a target string after validation and normalisation. Exactly
// one of Addr, Prefix and Host is meaningful, according to Kind.
type ParsedTarget struct {
	Raw    string // as supplied, trimmed
	Kind   string // KindIP, KindIPv6, KindCIDR, KindHostname, KindDomain, KindURL
	Addr   netip.Addr
	Prefix netip.Prefix
	Host   string // lowercased, no trailing dot, no port (hostname/domain/url)
	Scheme string // url only, lowercased
}

// IsIP reports whether the parsed target resolved to a single address.
func (p ParsedTarget) IsIP() bool { return p.Kind == KindIP || p.Kind == KindIPv6 }

// ParseTarget validates and normalises a single target string. Accepted
// shapes: IPv4, IPv6 (any RFC 5952 form, no zone), IPv4/IPv6 CIDR, RFC 1123
// hostname, multi-label domain, and an absolute http(s) URL whose host is
// extracted.
//
// Everything else — empty input, embedded whitespace, uppercase-only junk,
// host:port without a scheme, unsupported URL schemes, oversized labels,
// malformed CIDRs — returns an error wrapping ErrInvalidTarget.
func ParseTarget(raw string) (ParsedTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedTarget{}, fmt.Errorf("%w: empty target", ErrInvalidTarget)
	}
	if strings.ContainsAny(trimmed, " \t\r\n\x00") {
		return ParsedTarget{}, fmt.Errorf("%w: %q contains whitespace", ErrInvalidTarget, raw)
	}

	// URL: only absolute http(s) URLs are meaningful scan targets.
	if i := strings.Index(trimmed, "://"); i >= 0 {
		return parseURL(trimmed, raw)
	}

	// CIDR, both families. netip requires a valid prefix: host bits may be
	// set (they are masked for matching) but the length must be in range.
	if strings.Contains(trimmed, "/") {
		pre, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return ParsedTarget{}, fmt.Errorf("%w: %q is not a valid CIDR: %v", ErrInvalidTarget, raw, err)
		}
		return ParsedTarget{Raw: trimmed, Kind: KindCIDR, Prefix: pre.Masked()}, nil
	}

	// Bare IP literal. Zones are rejected: they are link-local scope
	// identifiers that do not survive routing.
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		if addr.Zone() != "" {
			return ParsedTarget{}, fmt.Errorf("%w: %q has an address zone", ErrInvalidTarget, raw)
		}
		return ipTarget(trimmed, addr.Unmap()), nil
	}

	host, err := normalizeHost(trimmed)
	if err != nil {
		return ParsedTarget{}, err
	}
	kind := KindHostname
	if strings.Contains(host, ".") {
		// A multi-label entry is a domain: it authorises the host itself and
		// its subdomains, which matches how practitioners scope assessments.
		// Use target_type "hostname" to pin an entry to an exact host.
		kind = KindDomain
	}
	return ParsedTarget{Raw: trimmed, Kind: kind, Host: host}, nil
}

func ipTarget(raw string, addr netip.Addr) ParsedTarget {
	kind := KindIP
	if addr.Is6() {
		kind = KindIPv6
	}
	return ParsedTarget{Raw: raw, Kind: kind, Addr: addr}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseURL(trimmed, raw string) (ParsedTarget, error) {
	u, err := url.Parse(trimmed)
	if err != nil {
		return ParsedTarget{}, fmt.Errorf("%w: %q is not a valid URL: %v", ErrInvalidTarget, raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ParsedTarget{}, fmt.Errorf("%w: %q uses unsupported scheme %q", ErrInvalidTarget, raw, u.Scheme)
	}
	if u.Host == "" {
		return ParsedTarget{}, fmt.Errorf("%w: %q has no host", ErrInvalidTarget, raw)
	}
	host := u.Hostname() // strips the port and the IPv6 brackets
	if host == "" {
		return ParsedTarget{}, fmt.Errorf("%w: %q has no host", ErrInvalidTarget, raw)
	}
	// Security: reject URLs whose userinfo (user@host) makes the authorized
	// string diverge from the scanned host — evil.example@127.0.0.1 reads as
	// evil.example but scans 127.0.0.1. It has no scanning purpose.
	if u.User != nil {
		return ParsedTarget{}, fmt.Errorf("%w: %q must not contain userinfo", ErrInvalidTarget, raw)
	}
	// Query and fragment carry no scanning meaning and are canonical
	// surfaces for log/label spoofing: strip them. (The path is kept: web
	// scanners may use it; port scanners ignore it.)
	if i := strings.IndexAny(trimmed, "?#"); i >= 0 {
		trimmed = trimmed[:i]
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return ParsedTarget{}, fmt.Errorf("%w: %q has an address zone", ErrInvalidTarget, raw)
		}
		t := ipTarget(trimmed, addr.Unmap())
		t.Scheme = scheme
		return t, nil
	}
	norm, err := normalizeHost(host)
	if err != nil {
		return ParsedTarget{}, err
	}
	// A URL names one service endpoint, so it authorises exactly that host.
	return ParsedTarget{Raw: trimmed, Kind: KindHostname, Host: norm, Scheme: scheme}, nil
}

// normalizeHost lowercases a hostname, drops one optional trailing dot and
// enforces RFC 1123 label rules.
func normalizeHost(h string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(h, "."))
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("%w: %q is not a valid hostname", ErrInvalidTarget, h)
	}
	labels := strings.Split(host, ".")
	// RFC 1123 section 2.1: the last label of a hostname must not be all
	// digits, so that addresses and hostnames stay distinguishable. Without
	// this rule "10.0.0.256" (an invalid IP) would silently become a domain.
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: %q looks like an address but is not a valid one", ErrInvalidTarget, h)
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("%w: %q has an empty or oversized label", ErrInvalidTarget, h)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: %q has a label starting or ending with '-'", ErrInvalidTarget, h)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
			if !ok {
				return "", fmt.Errorf("%w: %q contains the invalid character %q", ErrInvalidTarget, h, string(c))
			}
		}
	}
	return host, nil
}

// Entry is one configured project target: an included or excluded rule.
type Entry struct {
	Target     string
	TargetType string
	Excluded   bool
}

// effectiveKind resolves how a stored entry participates in matching.
//
// target_type "auto" uses the shape detected by ParseTarget. An explicit type
// is authoritative: "hostname" pins a rule to one exact host (no subdomains),
// "domain" enables label-boundary suffix matching, and the IP/CIDR types
// require the stored text to actually have that shape — an entry that does not
// parse, or does not match its declared type, is inert and never authorises
// anything.
func effectiveKind(e Entry) (ParsedTarget, string, bool) {
	p, err := ParseTarget(e.Target)
	if err != nil {
		return ParsedTarget{}, "", false
	}
	switch e.TargetType {
	case "", KindAuto:
		return p, p.Kind, true
	case KindIP:
		if p.Kind != KindIP {
			return ParsedTarget{}, "", false
		}
		return p, KindIP, true
	case KindIPv6:
		if p.Kind != KindIPv6 {
			return ParsedTarget{}, "", false
		}
		return p, KindIPv6, true
	case KindCIDR:
		if p.Kind != KindCIDR {
			return ParsedTarget{}, "", false
		}
		return p, KindCIDR, true
	case KindHostname:
		if p.Host == "" {
			return ParsedTarget{}, "", false
		}
		return p, KindHostname, true
	case KindDomain:
		if p.Host == "" {
			return ParsedTarget{}, "", false
		}
		return p, KindDomain, true
	case KindURL:
		if p.Host == "" {
			return ParsedTarget{}, "", false
		}
		return p, KindHostname, true // a URL entry pins one exact host
	default:
		return p, p.Kind, true
	}
}

// matchesEntry reports whether a parsed target is covered by one entry.
//
// There is deliberately no DNS resolution here: an IP target can only be
// authorised by an IP or CIDR entry, and a hostname target only by a hostname
// or domain entry. A target that rebinds between DNS names and addresses must
// be authorised in both forms.
func matchesEntry(t ParsedTarget, kind string, e ParsedTarget) bool {
	switch kind {
	case KindIP, KindIPv6:
		switch {
		case t.IsIP():
			return t.Addr == e.Addr
		case t.Kind == KindCIDR:
			// A /32 or /128 entry authorises exactly that one address, so a
			// CIDR target is covered only when it is that single address.
			return t.Prefix.Addr() == e.Addr && t.Prefix.Bits() == addrBits(e.Addr)
		default:
			return false
		}

	case KindCIDR:
		switch {
		case t.IsIP():
			return e.Prefix.Contains(t.Addr)
		case t.Kind == KindCIDR:
			// The whole requested range must sit inside the authorised range.
			if t.Prefix.Addr().Is4() != e.Prefix.Addr().Is4() {
				return false
			}
			return e.Prefix.Bits() <= t.Prefix.Bits() && e.Prefix.Contains(t.Prefix.Addr())
		default:
			return false
		}

	case KindHostname:
		return t.Host != "" && strings.EqualFold(t.Host, e.Host)

	case KindDomain:
		if t.Host == "" {
			return false
		}
		return t.Host == e.Host || strings.HasSuffix(t.Host, "."+e.Host)

	default:
		return false
	}
}

func addrBits(a netip.Addr) int {
	if a.Is4() {
		return 32
	}
	return 128
}

// Check applies the authorization rules of a project to an already parsed
// target:
//
//  1. no entry may be an exclusion that matches the target — exclusions always
//     win, even when an include also matches, so a stray "allow all" can never
//     re-authorise a host the assessor took out of scope;
//  2. at least one included entry must match. A project with no included
//     entries authorises nothing (fail closed).
//
// It returns nil when the target is in scope, ErrExcluded when an exclusion
// matched and ErrNotAuthorized otherwise.
func Check(t ParsedTarget, entries []Entry) error {
	var matchedInclude bool
	for _, e := range entries {
		parsed, kind, ok := effectiveKind(e)
		if !ok {
			continue // inert entry: unparseable or inconsistent with its type
		}
		if !matchesEntry(t, kind, parsed) {
			continue
		}
		if e.Excluded {
			return fmt.Errorf("%w: %q matches excluded entry %q", ErrExcluded, t.Raw, e.Target)
		}
		matchedInclude = true
	}
	if !matchedInclude {
		return fmt.Errorf("%w: %q is not covered by any included target of this project", ErrNotAuthorized, t.Raw)
	}
	return nil
}

// checkString parses and checks in one step; used by the tests and by callers
// that only hold the raw string.
func checkString(raw string, entries []Entry) error {
	t, err := ParseTarget(raw)
	if err != nil {
		return err
	}
	return Check(t, entries)
}
