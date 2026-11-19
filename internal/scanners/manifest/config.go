package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/mauropm/wadjet/internal/scanners"
)

// unsafeValueRe is the baseline character filter for free-form string option
// values: letters, digits and a small punctuation set only. Spaces, shell
// metacharacters, glob characters and control characters never pass. This is
// defense in depth — individual scanners still apply stricter per-option
// regexes before any value may reach argv.
var unsafeValueRe = regexp.MustCompile("[^A-Za-z0-9,:._@/+=\\-]")

// ValidateConfig checks a user-supplied scanner configuration against the
// manifest option declarations. Unknown keys are rejected: configuration
// outside the manifest is not accepted, per the Scanner contract.
//
// String-shaped values additionally pass a baseline "no shell metacharacters
// or control characters" filter. This is defense in depth: adapters must
// still apply their own strict per-option validation before argv.
func ValidateConfig(opts []OptionSpec, config scanners.ScannerConfig) error {
	declared := make(map[string]*OptionSpec, len(opts))
	for i := range opts {
		declared[opts[i].ID] = &opts[i]
	}
	for key := range config {
		if _, ok := declared[key]; !ok {
			return fmt.Errorf("unknown configuration option %q", key)
		}
	}
	for _, spec := range opts {
		raw, ok := config[spec.ID]
		if !ok || raw == nil {
			continue
		}
		if err := validateOption(spec, raw); err != nil {
			return fmt.Errorf("option %q: %w", spec.ID, err)
		}
	}
	return nil
}

func validateOption(spec OptionSpec, raw any) error {
	switch spec.Type {
	case OptionBoolean:
		if _, ok := raw.(bool); !ok {
			return fmt.Errorf("expected boolean, got %T", raw)
		}
	case OptionNumber:
		f, err := toFloat(raw)
		if err != nil {
			return err
		}
		if spec.Min != nil && f < *spec.Min {
			return fmt.Errorf("%v below minimum %v", f, *spec.Min)
		}
		if spec.Max != nil && f > *spec.Max {
			return fmt.Errorf("%v above maximum %v", f, *spec.Max)
		}
	case OptionString:
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", raw)
		}
		if err := checkSafeString(s, 512); err != nil {
			return err
		}
	case OptionSelect:
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", raw)
		}
		if !containsString(spec.Options, s) {
			return fmt.Errorf("%q not in allowed set {%s}", s, strings.Join(spec.Options, ","))
		}
	case OptionMultiselect:
		list, err := toStringList(raw)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return fmt.Errorf("expected at least one value")
		}
		for _, v := range list {
			if !containsString(spec.Options, v) {
				return fmt.Errorf("%q not in allowed set {%s}", v, strings.Join(spec.Options, ","))
			}
		}
	default:
		return fmt.Errorf("option type %q unknown", spec.Type)
	}
	return nil
}

func checkSafeString(s string, max int) error {
	if len(s) == 0 {
		return fmt.Errorf("value must not be empty")
	}
	if len(s) > max {
		return fmt.Errorf("value exceeds %d characters", max)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("value contains control characters")
		}
	}
	if unsafeValueRe.MatchString(s) {
		return fmt.Errorf("value %q contains characters outside the safe set", s)
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("value %q must not start with a dash (looks like a flag)", s)
	}
	return nil
}

func toFloat(raw any) (float64, error) {
	switch v := raw.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return 0, fmt.Errorf("expected number, got %q", v.String())
		}
		return f, nil
	default:
		return 0, fmt.Errorf("expected number, got %T", raw)
	}
}

func toStringList(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("list element %v is not a string", e)
			}
			out = append(out, s)
		}
		return out, nil
	case string:
		var list []string
		if err := json.Unmarshal([]byte(v), &list); err == nil {
			return list, nil
		}
		return []string{v}, nil
	default:
		return nil, fmt.Errorf("expected list of strings, got %T", raw)
	}
}

// StringList normalizes a multiselect/string config value to []string. It is
// intended for adapter implementations after ValidateConfig has passed.
func StringList(raw any) ([]string, bool) {
	list, err := toStringList(raw)
	if err != nil {
		return nil, false
	}
	return list, true
}

// BoolConfig returns config[key] as a bool, defaulting to def.
func BoolConfig(config scanners.ScannerConfig, key string, def bool) bool {
	if v, ok := config[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

// StringConfig returns config[key] as a string, defaulting to def.
func StringConfig(config scanners.ScannerConfig, key string, def string) string {
	if v, ok := config[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// FloatConfig returns config[key] as a float64, defaulting to def.
func FloatConfig(config scanners.ScannerConfig, key string, def float64) float64 {
	if v, ok := config[key]; ok {
		if f, err := toFloat(v); err == nil {
			return f
		}
	}
	return def
}
