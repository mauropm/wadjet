// Package nativeprobe implements a pure-Go TCP connect probe scanner, the
// reference example of the "native" adapter kind: no external binary, runs
// in-process under the orchestrator's timeout and cancellation.
//
// It observes open TCP ports only and deliberately produces zero findings.
package nativeprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

// ParserKey identifies this scanner in a manifest's output.parser field.
const ParserKey = "tcp_connect_probe"

// Option keys.
const (
	OptPorts          = "ports"
	OptConnectTimeout = "connect_timeout_ms"
	OptConcurrency    = "concurrency"
)

var portsRe = regexp.MustCompile(`^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$`)

const (
	defaultPorts          = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
	defaultConnectTimeout = 2 * time.Second
	defaultConcurrency    = 64
	maxProbesPerTarget    = 4096
)

// OptionSpecs is the manifest option declaration for nativeprobe.
var OptionSpecs = []manifest.OptionSpec{
	{ID: OptPorts, Label: "TCP ports to probe", Type: manifest.OptionString, Default: defaultPorts},
	{ID: OptConnectTimeout, Label: "Connect timeout (ms)", Type: manifest.OptionNumber, Default: 2000.0,
		Min: ptr(100.0), Max: ptr(10000.0)},
	{ID: OptConcurrency, Label: "Probe concurrency", Type: manifest.OptionNumber, Default: 64.0,
		Min: ptr(1.0), Max: ptr(256.0)},
}

func ptr(f float64) *float64 { return &f }

// Scanner is the native TCP probe scanner.
type Scanner struct{}

// New constructs the native probe scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return "nativeprobe" }

// Version implements scanners.Scanner.
func (s *Scanner) Version() string { return "builtin" }

// Description implements scanners.Scanner.
func (s *Scanner) Description() string {
	return "In-process TCP connect probe: verifies listener state without external tools"
}

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() []scanners.Capability {
	return []scanners.Capability{scanners.CapHostDiscovery, scanners.CapPortDiscovery}
}

// ValidateConfig implements scanners.Scanner.
func (s *Scanner) ValidateConfig(config scanners.ScannerConfig) error {
	if err := manifest.ValidateConfig(OptionSpecs, config); err != nil {
		return fmt.Errorf("nativeprobe: %w", err)
	}
	if raw, ok := config[OptPorts]; ok && raw != nil {
		ports, ok := raw.(string)
		if !ok {
			return fmt.Errorf("nativeprobe: %s must be a string", OptPorts)
		}
		if _, err := ParsePorts(ports); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTarget implements scanners.Scanner.
func (s *Scanner) ValidateTarget(t scanners.Target) error {
	switch t.Type {
	case "ip", "ipv6", "hostname":
		if t.Raw == "" || !hostLikeRe.MatchString(t.Raw) {
			return fmt.Errorf("nativeprobe: invalid target %q", t.Raw)
		}
		return nil
	default:
		return fmt.Errorf("nativeprobe: unsupported target type %q", t.Type)
	}
}

var hostLikeRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]{1,253}$`)

// ParsePorts validates and expands a port list like "80,443,8000-8010".
func ParsePorts(spec string) ([]int, error) {
	if spec == "" || !portsRe.MatchString(spec) {
		return nil, fmt.Errorf("nativeprobe: ports %q rejected by validation", spec)
	}
	var ports []int
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		loS, hiS, _ := strings.Cut(part, "-")
		lo, err := strconv.Atoi(loS)
		if err != nil || lo < 1 || lo > 65535 {
			return nil, fmt.Errorf("nativeprobe: port %q out of range 1-65535", part)
		}
		hi := lo
		if hiS != "" {
			hi, err = strconv.Atoi(hiS)
			if err != nil || hi < 1 || hi > 65535 || hi < lo {
				return nil, fmt.Errorf("nativeprobe: range %q invalid", part)
			}
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
			if len(ports) > maxProbesPerTarget {
				return nil, fmt.Errorf("nativeprobe: more than %d ports requested", maxProbesPerTarget)
			}
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("nativeprobe: empty port set")
	}
	return ports, nil
}

// Execute probes every (target, port) pair concurrently under ctx.
func (s *Scanner) Execute(ctx context.Context, req scanners.ScanRequest) (*scanners.ScanResult, error) {
	if err := s.ValidateConfig(req.Config); err != nil {
		return nil, err
	}
	portsSpec := manifest.StringConfig(req.Config, OptPorts, defaultPorts)
	ports, err := ParsePorts(portsSpec)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(manifest.FloatConfig(req.Config, OptConnectTimeout, float64(defaultConnectTimeout/time.Millisecond))) * time.Millisecond
	concurrency := int(manifest.FloatConfig(req.Config, OptConcurrency, defaultConcurrency))
	if concurrency < 1 {
		concurrency = 1
	}

	result := &scanners.ScanResult{}
	var mu sync.Mutex
	byTarget := map[string]*scanners.AssetObservationData{}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	type job struct {
		target, host string
		port         int
	}
	jobs := make(chan job)

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			state := probeTCP(ctx, net.JoinHostPort(j.host, strconv.Itoa(j.port)), timeout)
			<-sem
			if state == "" {
				continue // unreachable and not "closed": skip noisy entries
			}
			mu.Lock()
			obs, ok := byTarget[j.target]
			if !ok {
				obs = &scanners.AssetObservationData{Identity: j.target}
				if addr, err := netip.ParseAddr(j.host); err == nil {
					if addr.Is4() {
						obs.IPv4 = j.host
					} else {
						obs.IPv6 = j.host
					}
				}
				byTarget[j.target] = obs
			}
			obs.Ports = append(obs.Ports, scanners.PortObservation{
				Port: j.port, Protocol: "tcp", State: state,
			})
			mu.Unlock()
		}
	}

	nWorkers := concurrency
	if nWorkers > len(req.Targets)*len(ports) {
		nWorkers = len(req.Targets) * len(ports)
	}
	if nWorkers < 1 {
		nWorkers = 1
	}
	for i := 0; i < nWorkers; i++ {
		wg.Add(1)
		go worker()
	}

dispatch:
	for _, t := range req.Targets {
		if err := s.ValidateTarget(t); err != nil {
			result.Errors = append(result.Errors, scanners.ScannerError{Target: t.Raw, Error: err.Error()})
			continue
		}
		hosts := []string{t.Raw}
		if t.Type == "hostname" {
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			addrs, err := net.DefaultResolver.LookupHost(resolveCtx, t.Raw)
			cancel()
			if err != nil || len(addrs) == 0 {
				result.Errors = append(result.Errors, scanners.ScannerError{Target: t.Raw, Error: fmt.Sprintf("resolve: %v", err)})
				continue
			}
			hosts = addrs
		}
		for _, h := range hosts {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					break dispatch
				case jobs <- job{target: strings.ToLower(t.Raw), host: h, port: p}:
				}
			}
		}
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		return nil, fmt.Errorf("nativeprobe: %w", ctx.Err())
	}

	for _, obs := range byTarget {
		sortPorts(obs.Ports)
		result.Assets = append(result.Assets, *obs)
	}
	// Deliberately no findings: connect probes prove reachability, not risk.
	return result, nil
}

// probeTCP returns "open", "closed", or "" (unreachable/filtered-with-noise).
func probeTCP(ctx context.Context, addr string, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return "open"
	}
	var se *net.OpError
	if errors.As(err, &se) {
		if se.Timeout() {
			return "filtered"
		}
		if se.Err != nil && strings.Contains(strings.ToLower(se.Err.Error()), "refused") {
			return "closed"
		}
	}
	return ""
}

func sortPorts(ports []scanners.PortObservation) {
	for i := 1; i < len(ports); i++ {
		for j := i; j > 0 && ports[j-1].Port > ports[j].Port; j-- {
			ports[j-1], ports[j] = ports[j], ports[j-1]
		}
	}
}
