// Package config loads WADJET configuration from environment variables.
package config

import (
	"os"
	"strconv"
)

// Config holds all runtime configuration for the WADJET server.
type Config struct {
	Port    string
	Env     string
	DataDir string // base directory for persistent runtime data

	DatabaseURL string

	SessionSecret string
	AdminEmail    string
	AdminPassword string

	ReportDir     string
	RawOutputDir  string
	ScanWorkDir   string
	ScannerCfgDir string

	ScanConcurrency int
	ScanTimeout     int // seconds, default per-scan timeout
}

// Load builds a Config from environment variables with local-development defaults.
func Load() *Config {
	c := &Config{
		Port:            env("WADJET_PORT", "8080"),
		Env:             env("WADJET_ENV", "development"),
		DatabaseURL:     env("DATABASE_URL", "postgres://wadjet:***@localhost:5432/wadjet?sslmode=disable"),
		SessionSecret:   env("WADJET_SESSION_SECRET", "dev-se…e-me"),
		AdminEmail:      env("WADJET_ADMIN_EMAIL", "admin@wadjet.local"),
		AdminPassword:   env("WADJET_ADMIN_PASSWORD", "admin"),
		ReportDir:       env("WADJET_REPORT_DIR", "./data/reports"),
		RawOutputDir:    env("WADJET_RAW_OUTPUT_DIR", "./data/raw"),
		ScanWorkDir:     env("WADJET_SCAN_WORKDIR", "./data/scanwork"),
		ScannerCfgDir:   env("WADJET_SCANNER_CONFIG_DIR", "./configs/scanners"),
		ScanConcurrency: envInt("WADJET_SCAN_CONCURRENCY", 4),
		ScanTimeout:     envInt("WADJET_SCAN_TIMEOUT", 1800),
	}
	c.DataDir = "./data"
	return c
}

// IsDevelopment reports whether the server runs in development mode.
func (c *Config) IsDevelopment() bool { return c.Env != "production" }

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
