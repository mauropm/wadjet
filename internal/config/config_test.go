package config

import "testing"

// SEC-DEV-1: the no-login gate's env classification must be an allowlist
// ("exactly development"), never the fail-open != "production". Ambiguous
// or adversarial values must classify as NOT development.
func TestIsStrictDevelopment(t *testing.T) {
	strict := []string{"development", "Development", "DEVELOPMENT", " development ", "\tdevelopment\n"}
	for _, env := range strict {
		c := &Config{Env: env}
		if !c.IsStrictDevelopment() {
			t.Errorf("IsStrictDevelopment(%q) = false, want true", env)
		}
	}

	notStrict := []string{"", " ", "production", "Production", "PROD", "prod", "productio",
		"develop", "developer", "dev", "stagings", "production "}
	for _, env := range notStrict {
		c := &Config{Env: env}
		if c.IsStrictDevelopment() {
			t.Errorf("IsStrictDevelopment(%q) = true, want false", env)
		}
	}
}

// IsDevelopment keeps its historical fail-open semantics (only the exact
// string "production" disables it) — the strict gate is a separate,
// additional predicate. Pin the difference so a future refactor cannot
// silently conflate the two.
func TestIsDevelopmentVsStrict(t *testing.T) {
	c := &Config{Env: "Production"}
	if !c.IsDevelopment() {
		t.Error(`IsDevelopment("Production") = false, want true (fail-open by design)`)
	}
	if c.IsStrictDevelopment() {
		t.Error(`IsStrictDevelopment("Production") = true, want false (allowlist)`)
	}
}
