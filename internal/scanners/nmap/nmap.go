package nmap

import (
	"context"
	"fmt"

	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/adapters/command"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

// ParserKey is the manifest output.parser value that selects this scanner.
const ParserKey = "nmap_xml"

// Scanner implements scanners.Scanner for Nmap on top of the secure command
// adapter: argv comes from BuildArgs (allowlist-driven), execution happens
// through exec.CommandContext only, and XML output is parsed defensively.
type Scanner struct {
	*command.Adapter
}

// New builds an nmap scanner from a validated manifest.
func New(m *manifest.Manifest) (*Scanner, error) {
	adapter, err := command.NewWithArgBuilder(m, command.ParserFunc(Parse),
		func(req scanners.ScanRequest) ([]string, error) { return BuildArgs(m, req) })
	if err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}
	return &Scanner{Adapter: adapter}, nil
}

// ValidateConfig applies the manifest option schema plus nmap-specific
// strict validation of values that can influence argv.
func (s *Scanner) ValidateConfig(config scanners.ScannerConfig) error {
	if err := s.Adapter.ValidateConfig(config); err != nil {
		return err
	}
	_, err := BuildArgs(s.Manifest(), scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		Config:  config,
	})
	return err
}

// Execute runs nmap for the request.
func (s *Scanner) Execute(ctx context.Context, req scanners.ScanRequest) (*scanners.ScanResult, error) {
	return s.Adapter.Execute(ctx, req)
}
