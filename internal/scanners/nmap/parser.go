package nmap

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/mauropm/wadjet/internal/scanners"
)

// XML document shapes for nmap's -oX output. Field types are deliberately
// permissive (string attributes parsed manually) because scanner output is
// untrusted and malformed attributes must not abort a whole scan.

type nmapRun struct {
	XMLName  xml.Name      `xml:"nmaprun"`
	Scanner  string        `xml:"scanner,attr"`
	Version  string        `xml:"version,attr"`
	Args     string        `xml:"args,attr"`
	Hosts    []nmapHost    `xml:"host"`
	RunStats *nmapRunStats `xml:"runstats"`
}

type nmapRunStats struct {
	Hosts nmapHostCounts `xml:"hosts"`
}

type nmapHostCounts struct {
	Up      string `xml:"up,attr"`
	Down    string `xml:"down,attr"`
	Skipped string `xml:"skipped,attr"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     nmapPorts      `xml:"ports"`
	OS        *nmapOS        `xml:"os"`
	Scripts   []nmapScript   `xml:"hostscript>script"`
}

type nmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // ipv4, ipv6, mac
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"` // PTR, user
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   string       `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
}

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
	Line     string `xml:"line,attr"`
}

// nmapScript is one NSE script element, either host-level or port-level.
type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// Parse parses nmap XML output into normalized results. It never panics on
// hostile input and tolerates malformed attributes (recorded as errors).
func Parse(raw []byte) (*scanners.ScanResult, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("nmap: empty output")
	}
	var run nmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return nil, fmt.Errorf("nmap: malformed XML output: %w", err)
	}
	if run.XMLName.Local != "nmaprun" {
		return nil, fmt.Errorf("nmap: not an nmaprun document")
	}

	result := &scanners.ScanResult{RawOutput: raw}
	for i := range run.Hosts {
		h := &run.Hosts[i]
		obs, findings, errs := normalizeHost(h)
		result.Errors = append(result.Errors, errs...)
		if obs != nil {
			result.Assets = append(result.Assets, *obs)
			result.Findings = append(result.Findings, findings...)
		}
	}
	return result, nil
}

// normalizeHost converts one <host> element. It returns nil obs for hosts
// without any usable identity.
func normalizeHost(h *nmapHost) (*scanners.AssetObservationData, []scanners.FindingResult, []scanners.ScannerError) {
	var errs []scanners.ScannerError

	var ipv4, ipv6, mac string
	for _, a := range h.Addresses {
		switch a.AddrType {
		case "ipv4":
			if ipv4 == "" {
				ipv4 = a.Addr
			}
		case "ipv6":
			if ipv6 == "" {
				ipv6 = a.Addr
			}
		case "mac":
			if mac == "" {
				mac = a.Addr
			}
		}
	}

	var hostnames []string
	for _, hn := range h.Hostnames {
		name := strings.ToLower(strings.TrimSpace(hn.Name))
		if name == "" {
			continue
		}
		if !containsFold(hostnames, name) {
			hostnames = append(hostnames, name)
		}
	}

	identity := ipv4
	if identity == "" {
		identity = ipv6
	}
	if identity == "" && len(hostnames) > 0 {
		identity = hostnames[0]
	}
	if identity == "" {
		errs = append(errs, scanners.ScannerError{Target: "<unknown host>", Error: "host element without ipv4/ipv6/hostname address"})
		return nil, nil, errs
	}

	obs := &scanners.AssetObservationData{
		Identity:  identity,
		IPv4:      ipv4,
		IPv6:      ipv6,
		MAC:       mac,
		Hostnames: hostnames,
	}
	if h.Status.State != "" && h.Status.State != "up" {
		obs.Extra = map[string]any{"status": h.Status.State, "status_reason": h.Status.Reason}
	}

	if h.OS != nil {
		best := ""
		bestAcc := -1
		for _, om := range h.OS.Matches {
			acc, err := strconv.Atoi(strings.TrimSpace(om.Accuracy))
			if err != nil {
				errs = append(errs, scanners.ScannerError{
					Target: identity,
					Error:  fmt.Sprintf("unparseable osmatch accuracy %q", om.Accuracy),
				})
				continue
			}
			name := strings.TrimSpace(om.Name)
			if name != "" && acc > bestAcc {
				best, bestAcc = name, acc
			}
		}
		if bestAcc >= 0 {
			obs.OSName = best
			obs.OSAccuracy = bestAcc
		}
	}

	var findings []scanners.FindingResult
	scriptNotes := map[string]string{}

	for i := range h.Ports.Ports {
		p := &h.Ports.Ports[i]
		portNum, err := strconv.Atoi(strings.TrimSpace(p.PortID))
		if err != nil || portNum < 1 || portNum > 65535 {
			errs = append(errs, scanners.ScannerError{
				Target: identity,
				Error:  fmt.Sprintf("unparseable or out-of-range portid %q for %s port", p.PortID, p.Protocol),
			})
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(p.Protocol))
		if proto == "" {
			proto = "tcp"
		}
		po := scanners.PortObservation{
			Port:      portNum,
			Protocol:  proto,
			State:     normalizeState(p.State.State),
			Service:   strings.TrimSpace(p.Service.Name),
			Product:   strings.TrimSpace(p.Service.Product),
			Version:   strings.TrimSpace(p.Service.Version),
			ExtraInfo: strings.TrimSpace(p.Service.ExtraInfo),
		}
		obs.Ports = append(obs.Ports, po)

		for _, sc := range p.Scripts {
			fs := classifyScript(identity, &po, sc)
			if len(fs) > 0 {
				findings = append(findings, fs...)
			} else {
				scriptNotes[portScriptKey(po, sc.ID)] = sc.Output
			}
		}
	}

	for _, sc := range h.Scripts {
		fs := classifyScript(identity, nil, sc)
		if len(fs) > 0 {
			findings = append(findings, fs...)
		} else {
			scriptNotes["host:"+sc.ID] = sc.Output
		}
	}

	if len(scriptNotes) > 0 {
		if obs.Extra == nil {
			obs.Extra = map[string]any{}
		}
		obs.Extra["scripts"] = scriptNotes
	}

	return obs, findings, errs
}

func normalizeState(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "open", "closed", "filtered", "unfiltered":
		return strings.ToLower(strings.TrimSpace(s))
	case "open|filtered":
		return "open" // conservatively treat ambiguous states as open
	case "closed|filtered":
		return "closed"
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

func portScriptKey(po scanners.PortObservation, scriptID string) string {
	return fmt.Sprintf("%s/%d:%s", po.Protocol, po.Port, scriptID)
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
