package assets

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/mauropm/wadjet/internal/models"
)

// ErrNotFound is returned when no asset row matches.
var ErrNotFound = errors.New("asset not found")

// NormalizeIdentity turns free-form scanner or operator input into the
// canonical dedup key stored in assets.identity, together with the asset_type
// implied by its shape.
//
// Rules, applied in this order:
//
//  1. an optional "scheme://" prefix and any path/query/fragment are dropped,
//     so "https://Shop.Example.com/cart" describes the host shop.example.com;
//  2. a ":port" suffix is removed when there is exactly one colon and the
//     suffix is numeric (bracketed IPv6 literals keep their colons);
//  3. the result is lowercased and one trailing dot is removed;
//  4. a valid IP literal becomes its canonical netip text form, so
//     "2001:0DB8::0001" and "2001:db8::1" collapse to one asset and
//     IPv4-mapped addresses are unwrapped to IPv4;
//  5. otherwise the value must be a valid host name whose last label is not
//     all digits (RFC 1123 §2.1), which is what keeps a mistyped address such
//     as "10.0.0.256" from silently becoming a host name;
//  6. CIDR notation is rejected: an asset is one host, ranges belong in
//     project_targets.
//
// The returned asset type is models.AssetTypeIPv4 / AssetTypeIPv6 for
// addresses and models.AssetTypeHostname for host names; callers may override
// it explicitly when they know better (web_app, container, ...).
func NormalizeIdentity(raw string) (identity, assetType string, err error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", "", fmt.Errorf("%w: empty identity", ErrInvalidIdentity)
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return "", "", fmt.Errorf("%w: %q contains whitespace", ErrInvalidIdentity, raw)
	}

	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
		if j := strings.IndexAny(v, "/?#"); j >= 0 {
			v = v[:j]
		}
	}
	if strings.HasPrefix(v, "[") {
		end := strings.Index(v, "]")
		if end < 0 {
			return "", "", fmt.Errorf("%w: %q has an unbalanced bracket", ErrInvalidIdentity, raw)
		}
		v = v[1:end]
	} else if strings.Count(v, ":") == 1 {
		if i := strings.LastIndex(v, ":"); i > 0 && allDigits(v[i+1:]) {
			v = v[:i]
		}
	}
	v = strings.ToLower(strings.TrimSuffix(v, "."))
	if v == "" {
		return "", "", fmt.Errorf("%w: %q", ErrInvalidIdentity, raw)
	}
	if strings.Contains(v, "/") {
		return "", "", fmt.Errorf("%w: %q is a range, not a host", ErrInvalidIdentity, raw)
	}

	if addr, err := netip.ParseAddr(v); err == nil {
		if addr.Zone() != "" {
			return "", "", fmt.Errorf("%w: %q has an address zone", ErrInvalidIdentity, raw)
		}
		addr = addr.Unmap()
		kind := models.AssetTypeIPv4
		if addr.Is6() {
			kind = models.AssetTypeIPv6
		}
		return addr.String(), kind, nil
	}

	if !validHostChars(v) {
		return "", "", fmt.Errorf("%w: %q is not a valid host name", ErrInvalidIdentity, raw)
	}
	labels := strings.Split(v, ".")
	if allDigits(labels[len(labels)-1]) {
		return "", "", fmt.Errorf("%w: %q looks like an address but is not a valid one", ErrInvalidIdentity, raw)
	}
	return v, models.AssetTypeHostname, nil
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

// validHostChars accepts the host syntax that may legitimately appear as an
// asset identity: RFC 1123 labels plus the underscore that shows up in service
// records and in scanner PTR output.
func validHostChars(v string) bool {
	if len(v) == 0 || len(v) > 253 {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// validAssetType mirrors the assets.asset_type CHECK constraint.
func validAssetType(t string) bool {
	switch t {
	case models.AssetTypeIPv4, models.AssetTypeIPv6, models.AssetTypeHostname,
		models.AssetTypeDomain, models.AssetTypeServer, models.AssetTypeEndpoint,
		models.AssetTypeWebApp, models.AssetTypeContainer, models.AssetTypeOther:
		return true
	default:
		return false
	}
}

// validStatus mirrors the assets.status CHECK constraint.
func validStatus(s string) bool {
	switch s {
	case "active", "inactive", "retired":
		return true
	default:
		return false
	}
}

// validObservationType mirrors the asset_observations.observation_type CHECK.
func validObservationType(t string) bool {
	switch t {
	case "network", "service", "tls", "web", "vulnerability", "manual":
		return true
	default:
		return false
	}
}

// domainOf returns the parent of a host name: everything after the first
// label, or "" when there is nothing left to strip.
func domainOf(host string) string {
	i := strings.Index(host, ".")
	if i <= 0 || i == len(host)-1 {
		return ""
	}
	parent := host[i+1:]
	if !validHostChars(parent) {
		return ""
	}
	return parent
}
