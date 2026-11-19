package targets

import (
	"errors"
	"strings"
	"testing"
)

func ent(target, typ string, excluded bool) Entry {
	return Entry{Target: target, TargetType: typ, Excluded: excluded}
}

// TestAuthorizeTable is the regression suite for the security gate. Every case
// is evaluated without a database through Check, so the matching rules are
// pinned independently of storage.
func TestAuthorizeTable(t *testing.T) {
	cases := []struct {
		name    string
		entries []Entry
		target  string
		want    error
	}{
		// ── exact addresses
		{
			name:    "ipv4 exact include",
			entries: []Entry{ent("10.0.0.1", "auto", false)},
			target:  "10.0.0.1",
			want:    nil,
		},
		{
			name:    "ipv4 not in scope",
			entries: []Entry{ent("10.0.0.1", "auto", false)},
			target:  "10.0.0.2",
			want:    ErrNotAuthorized,
		},
		{
			name:    "ipv6 include written compressed, target expanded",
			entries: []Entry{ent("2001:db8::1", "auto", false)},
			target:  "2001:0DB8:0000:0000:0000:0000:0000:0001",
			want:    nil,
		},
		{
			name:    "ipv6 include expanded, target compressed",
			entries: []Entry{ent("2001:0db8:0000:0000:0000:0000:0000:0001", "auto", false)},
			target:  "2001:DB8::1",
			want:    nil,
		},
		{
			name:    "ipv6 loopback",
			entries: []Entry{ent("::1", "ipv6", false)},
			target:  "0:0:0:0:0:0:0:1",
			want:    nil,
		},
		{
			name:    "ipv6 zone is rejected",
			entries: []Entry{ent("fe80::1", "ipv6", false)},
			target:  "fe80::1%eth0",
			want:    ErrInvalidTarget,
		},
		{
			name:    "ipv4-mapped ipv6 target matches ipv4 entry",
			entries: []Entry{ent("10.0.0.5", "ip", false)},
			target:  "::ffff:10.0.0.5",
			want:    nil,
		},
		{
			name:    "ipv4-mapped ipv6 target does not match neighbouring entry",
			entries: []Entry{ent("10.0.0.5", "ip", false)},
			target:  "::ffff:10.0.0.6",
			want:    ErrNotAuthorized,
		},
		{
			name:    "ipv4 target matches entry stored as ipv4-mapped ipv6",
			entries: []Entry{ent("::ffff:10.0.0.5", "auto", false)},
			target:  "10.0.0.5",
			want:    nil,
		},
		{
			name:    "ipv6 entry never authorises an ipv4 host",
			entries: []Entry{ent("2001:db8::/32", "auto", false)},
			target:  "10.0.0.1",
			want:    ErrNotAuthorized,
		},

		// ── CIDR boundaries, both families
		{
			name:    "ipv4 cidr contains first address",
			entries: []Entry{ent("10.0.0.0/24", "auto", false)},
			target:  "10.0.0.0",
			want:    nil,
		},
		{
			name:    "ipv4 cidr contains last address",
			entries: []Entry{ent("10.0.0.0/24", "auto", false)},
			target:  "10.0.0.255",
			want:    nil,
		},
		{
			name:    "ipv4 cidr excludes the next block",
			entries: []Entry{ent("10.0.0.0/24", "auto", false)},
			target:  "10.0.1.0",
			want:    ErrNotAuthorized,
		},
		{
			name:    "ipv4 cidr entry with host bits set is masked",
			entries: []Entry{ent("10.0.0.55/24", "cidr", false)},
			target:  "10.0.0.9",
			want:    nil,
		},
		{
			name:    "ipv6 cidr contains address",
			entries: []Entry{ent("2001:db8::/32", "auto", false)},
			target:  "2001:0db8:0000:0001::5",
			want:    nil,
		},
		{
			name:    "ipv6 cidr excludes neighbouring prefix",
			entries: []Entry{ent("2001:db8::/32", "auto", false)},
			target:  "2001:db9::1",
			want:    ErrNotAuthorized,
		},
		{
			name:    "ipv6 /128 entry authorises only that address",
			entries: []Entry{ent("2001:db8::1/128", "auto", false)},
			target:  "2001:db8::1",
			want:    nil,
		},
		{
			name:    "ipv6 /128 entry rejects a different address",
			entries: []Entry{ent("2001:db8::1/128", "auto", false)},
			target:  "2001:db8::2",
			want:    ErrNotAuthorized,
		},
		{
			name:    "requested cidr fully inside authorised cidr",
			entries: []Entry{ent("10.0.0.0/16", "auto", false)},
			target:  "10.0.5.0/24",
			want:    nil,
		},
		{
			name:    "requested cidr wider than authorised cidr is denied",
			entries: []Entry{ent("10.0.5.0/24", "auto", false)},
			target:  "10.0.0.0/16",
			want:    ErrNotAuthorized,
		},
		{
			name:    "requested /25 fully inside the authorised /24",
			entries: []Entry{ent("10.0.0.0/24", "auto", false)},
			target:  "10.0.0.128/25",
			want:    nil,
		},
		{
			name:    "requested cidr straddling the boundary is denied",
			entries: []Entry{ent("10.0.0.0/25", "auto", false)},
			target:  "10.0.0.128/25",
			want:    ErrNotAuthorized,
		},
		{
			name:    "single address entry does not authorise a range",
			entries: []Entry{ent("10.0.0.0", "ip", false)},
			target:  "10.0.0.0/24",
			want:    ErrNotAuthorized,
		},
		{
			name:    "default route entry authorises everything in family",
			entries: []Entry{ent("0.0.0.0/0", "cidr", false)},
			target:  "203.0.113.7",
			want:    nil,
		},
		{
			name:    "ipv4 cidr does not authorise ipv6",
			entries: []Entry{ent("0.0.0.0/0", "cidr", false)},
			target:  "2001:db8::1",
			want:    ErrNotAuthorized,
		},
		{
			name:    "malformed prefix length",
			entries: []Entry{ent("10.0.0.0/24", "auto", false)},
			target:  "10.0.0.0/33",
			want:    ErrInvalidTarget,
		},

		// ── hostnames and domains
		{
			name:    "hostname exact match",
			entries: []Entry{ent("www.example.com", "hostname", false)},
			target:  "www.example.com",
			want:    nil,
		},
		{
			name:    "hostname match is case insensitive for the target",
			entries: []Entry{ent("www.example.com", "hostname", false)},
			target:  "WWW.Example.COM",
			want:    nil,
		},
		{
			name:    "hostname entry stored in mixed case",
			entries: []Entry{ent("WWW.Example.COM", "hostname", false)},
			target:  "www.example.com",
			want:    nil,
		},
		{
			name:    "hostname entry does not authorise a subdomain",
			entries: []Entry{ent("www.example.com", "hostname", false)},
			target:  "cdn.www.example.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "hostname entry does not authorise its parent domain",
			entries: []Entry{ent("www.example.com", "hostname", false)},
			target:  "example.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "explicit domain entry authorises itself",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "example.com",
			want:    nil,
		},
		{
			name:    "explicit domain entry authorises deep subdomains",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "a.b.c.example.com",
			want:    nil,
		},
		{
			name:    "suffix trap: hyphenated lookalike is denied",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "evil-example.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "suffix trap: prefixed lookalike is denied",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "notexample.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "suffix trap: lookalike subdomain is denied",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "www.evil-example.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "suffix trap: parent of the domain is denied",
			entries: []Entry{ent("shop.example.com", "domain", false)},
			target:  "example.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "auto multi-label entry behaves as a domain",
			entries: []Entry{ent("example.com", "auto", false)},
			target:  "shop.example.com",
			want:    nil,
		},
		{
			name:    "single label host is matched exactly",
			entries: []Entry{ent("intranet", "auto", false)},
			target:  "INTRANET",
			want:    nil,
		},
		{
			name:    "single label host does not authorise a subdomain",
			entries: []Entry{ent("intranet", "auto", false)},
			target:  "www.intranet",
			want:    ErrNotAuthorized,
		},
		{
			name:    "hostname entry does not authorise an unrelated ip",
			entries: []Entry{ent("www.example.com", "hostname", false)},
			target:  "93.184.216.34",
			want:    ErrNotAuthorized,
		},

		// ── URLs
		{
			name:    "https url matches hostname entry ignoring port and path",
			entries: []Entry{ent("shop.example.com", "hostname", false)},
			target:  "https://Shop.Example.COM:8443/cart?id=1",
			want:    nil,
		},
		{
			name:    "http url matches domain entry",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "http://shop.example.com/login",
			want:    nil,
		},
		{
			name:    "url with ip host matches ip entry",
			entries: []Entry{ent("10.0.0.5", "ip", false)},
			target:  "http://10.0.0.5/admin",
			want:    nil,
		},
		{
			name:    "url entry pins its exact host only",
			entries: []Entry{ent("https://shop.example.com/", "url", false)},
			target:  "cdn.shop.example.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "url entry matches its own host",
			entries: []Entry{ent("https://shop.example.com/", "url", false)},
			target:  "https://shop.example.com/",
			want:    nil,
		},
		{
			name:    "unsupported url scheme",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "ftp://example.com/file",
			want:    ErrInvalidTarget,
		},
		{
			name:    "scheme-less url separator is invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "//example.com",
			want:    ErrInvalidTarget,
		},
		{
			name:    "url without host",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "https://",
			want:    ErrInvalidTarget,
		},
		{
			name:    "url to a host outside scope",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "https://evil-example.com/",
			want:    ErrNotAuthorized,
		},

		// ── exclusions
		{
			name: "exclusion wins over a matching inclusion",
			entries: []Entry{
				ent("10.0.0.0/24", "auto", false),
				ent("10.0.0.9", "auto", true),
			},
			target: "10.0.0.9",
			want:   ErrExcluded,
		},
		{
			name: "sibling address inside the inclusion is still fine",
			entries: []Entry{
				ent("10.0.0.0/24", "auto", false),
				ent("10.0.0.9", "auto", true),
			},
			target: "10.0.0.10",
			want:   nil,
		},
		{
			name: "exclusion order does not matter",
			entries: []Entry{
				ent("10.0.0.9", "auto", true),
				ent("10.0.0.0/24", "auto", false),
			},
			target: "10.0.0.9",
			want:   ErrExcluded,
		},
		{
			name: "excluded domain wins over included domain",
			entries: []Entry{
				ent("example.com", "domain", false),
				ent("admin.example.com", "domain", true),
			},
			target: "admin.example.com",
			want:   ErrExcluded,
		},
		{
			name: "excluded domain leaves other subdomains authorized",
			entries: []Entry{
				ent("example.com", "domain", false),
				ent("admin.example.com", "domain", true),
			},
			target: "www.example.com",
			want:   nil,
		},
		{
			name: "exclusion without any inclusion fails closed",
			entries: []Entry{
				ent("10.0.0.0/8", "auto", true),
			},
			target: "10.0.0.1",
			want:   ErrExcluded,
		},
		{
			name: "exclusion of a range covering the target",
			entries: []Entry{
				ent("192.168.0.0/16", "auto", false),
				ent("192.168.1.0/24", "auto", true),
			},
			target: "192.168.1.55",
			want:   ErrExcluded,
		},
		{
			name:    "project without any target authorises nothing",
			entries: nil,
			target:  "10.0.0.1",
			want:    ErrNotAuthorized,
		},

		// ── inert entries
		{
			name:    "entry declared ip but holding a hostname is inert",
			entries: []Entry{ent("www.example.com", "ip", false)},
			target:  "www.example.com",
			want:    ErrNotAuthorized,
		},
		{
			name:    "entry declared cidr but holding an ip is inert",
			entries: []Entry{ent("10.0.0.1", "cidr", false)},
			target:  "10.0.0.1",
			want:    ErrNotAuthorized,
		},
		{
			name:    "unparseable entry is inert and harmless",
			entries: []Entry{ent("!!!garbage!!!", "auto", false), ent("10.0.0.1", "auto", false)},
			target:  "10.0.0.1",
			want:    nil,
		},
		{
			name:    "unparseable excluded entry cannot exclude",
			entries: []Entry{ent("!!!", "auto", true), ent("10.0.0.0/24", "auto", false)},
			target:  "10.0.0.1",
			want:    nil,
		},

		// ── malformed input
		{name: "empty target", entries: []Entry{ent("10.0.0.1", "auto", false)}, target: "", want: ErrInvalidTarget},
		{name: "blank target", entries: []Entry{ent("10.0.0.1", "auto", false)}, target: "   ", want: ErrInvalidTarget},
		{
			name:    "surrounding whitespace is tolerated",
			entries: []Entry{ent("10.0.0.1", "auto", false)},
			target:  "  10.0.0.1\t",
			want:    nil,
		},
		{
			name:    "embedded whitespace is invalid",
			entries: []Entry{ent("10.0.0.1", "auto", false)},
			target:  "10.0.0. 1",
			want:    ErrInvalidTarget,
		},
		{
			name:    "hostname with port but no scheme is invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "example.com:8080",
			want:    ErrInvalidTarget,
		},
		{
			name:    "double dot hostname is invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "www..example.com",
			want:    ErrInvalidTarget,
		},
		{
			name:    "label starting with a hyphen is invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "-bad.example.com",
			want:    ErrInvalidTarget,
		},
		{
			name:    "label ending with a hyphen is invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "bad-.example.com",
			want:    ErrInvalidTarget,
		},
		{
			name:    "underscore is not RFC1123",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "_dmarc.example.com",
			want:    ErrInvalidTarget,
		},
		{
			name:    "oversized label is invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  strings.Repeat("a", 64) + ".example.com",
			want:    ErrInvalidTarget,
		},
		{
			name:    "63 character label is accepted",
			entries: []Entry{ent(strings.Repeat("a", 63)+".example.com", "domain", false)},
			target:  strings.Repeat("a", 63) + ".example.com",
			want:    nil,
		},
		{
			name:    "trailing dot on a hostname target is accepted",
			entries: []Entry{ent("www.example.com", "hostname", false)},
			target:  "www.example.com.",
			want:    nil,
		},
		{
			name:    "shell metacharacters are invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "example.com;rm -rf /",
			want:    ErrInvalidTarget,
		},
		{
			// SEC-001 PoC: userinfo must not smuggle a different scanned host.
			name:    "url userinfo is rejected",
			entries: []Entry{ent("evil.example.com", "hostname", false)},
			target:  "http://evil.example.com@127.0.0.1/",
			want:    ErrInvalidTarget,
		},
		{
			// SEC-001 PoC: no command-substitution strings survive parsing.
			name:    "command substitution in url is rejected",
			entries: []Entry{ent("127.0.0.1", "ip", false)},
			target:  "http://$(touch /tmp/pwned)",
			want:    ErrInvalidTarget,
		},
		{
			name:    "sql fragment is invalid",
			entries: []Entry{ent("example.com", "domain", false)},
			target:  "10.0.0.1' OR '1'='1",
			want:    ErrInvalidTarget,
		},
		{
			name:    "ipv4 octet out of range",
			entries: []Entry{ent("10.0.0.1", "auto", false)},
			target:  "10.0.0.256",
			want:    ErrInvalidTarget,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkString(tc.target, tc.entries)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("authorize(%q) = %v, want nil", tc.target, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("authorize(%q) = %v, want %v", tc.target, err, tc.want)
			}
		})
	}
}

// TestParseTargetKinds pins the detected shape of every accepted syntax, which
// drives how an "auto" entry is interpreted.
func TestParseTargetKinds(t *testing.T) {
	cases := []struct {
		raw      string
		kind     string
		host     string
		hasAddr  bool
		hasBlock bool
	}{
		{raw: "10.0.0.1", kind: KindIP, hasAddr: true},
		{raw: "2001:db8::1", kind: KindIPv6, hasAddr: true},
		{raw: "10.0.0.0/24", kind: KindCIDR, hasBlock: true},
		{raw: "2001:db8::/32", kind: KindCIDR, hasBlock: true},
		{raw: "example.com", kind: KindDomain, host: "example.com"},
		{raw: "www.example.com", kind: KindDomain, host: "www.example.com"},
		{raw: "intranet", kind: KindHostname, host: "intranet"},
		{raw: "WWW.Example.COM", kind: KindDomain, host: "www.example.com"},
		{raw: "https://Shop.Example.com/x", kind: KindHostname, host: "shop.example.com"},
		{raw: "http://10.0.0.5/x", kind: KindIP, hasAddr: true},
	}
	for _, tc := range cases {
		p, err := ParseTarget(tc.raw)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", tc.raw, err)
		}
		if p.Kind != tc.kind {
			t.Errorf("ParseTarget(%q).Kind = %q, want %q", tc.raw, p.Kind, tc.kind)
		}
		if p.Host != tc.host {
			t.Errorf("ParseTarget(%q).Host = %q, want %q", tc.raw, p.Host, tc.host)
		}
		if got := p.Addr.IsValid(); got != tc.hasAddr {
			t.Errorf("ParseTarget(%q) valid addr = %v, want %v", tc.raw, got, tc.hasAddr)
		}
		if got := p.Prefix.IsValid(); got != tc.hasBlock {
			t.Errorf("ParseTarget(%q) valid prefix = %v, want %v", tc.raw, got, tc.hasBlock)
		}
	}
}

// TestIPNormalizationIsCanonical guards the ipv6 equality rule: two textual
// spellings of the same address must produce equal Addr values.
func TestIPNormalizationIsCanonical(t *testing.T) {
	a, err := ParseTarget("2001:0DB8:0000:0000:0000:0000:0000:0001")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseTarget("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Addr != b.Addr {
		t.Fatalf("ipv6 spellings not equal: %v vs %v", a.Addr, b.Addr)
	}
	if b.Addr.String() != "2001:db8::1" {
		t.Fatalf("canonical form = %s", b.Addr.String())
	}
}
