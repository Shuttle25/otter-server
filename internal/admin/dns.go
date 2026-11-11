package admin

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Resolver is net.Resolver's LookupIP (a fake in tests).
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type DNSResult struct {
	Label, Host         string
	Skipped, OK         bool
	Missing, Unexpected []string
	Err                 string
}

// DNSRecords lists the A/AAAA records every node hostname needs (docs/11 §5).
func DNSRecords(dir string) (string, error) {
	st, err := LoadState(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("; Add these records at the DNS provider of each domain (TTL 300 recommended)\n")
	for _, n := range st.Nodes {
		host := n.Endpoints[0].Host
		if net.ParseIP(host) != nil {
			continue
		}
		ips, err := NodeIPs(dir, n.Label)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			fmt.Fprintf(&b, "; %s: no IPs recorded (node set-ip --label %s --ip ...)\n", n.Label, n.Label)
		}
		for _, a := range ips {
			typ := "A   "
			if net.ParseIP(a).To4() == nil {
				typ = "AAAA"
			}
			fmt.Fprintf(&b, "%s.    300  IN  %s  %s\n", host, typ, a)
		}
	}
	return b.String(), nil
}

// CheckDNS resolves each node hostname (or only label) and compares with the recorded IPs.
func CheckDNS(ctx context.Context, dir, label string, r Resolver) ([]DNSResult, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	var out []DNSResult
	for _, n := range st.Nodes {
		if label != "" && n.Label != label {
			continue
		}
		res := DNSResult{Label: n.Label, Host: n.Endpoints[0].Host}
		if net.ParseIP(res.Host) != nil {
			res.Skipped, res.OK = true, true
			out = append(out, res)
			continue
		}
		want, err := NodeIPs(dir, n.Label)
		if err != nil {
			return nil, err
		}
		got, err := r.LookupIP(ctx, "ip", res.Host)
		if err != nil {
			res.Err = err.Error()
			out = append(out, res)
			continue
		}
		gotSet := map[string]bool{}
		for _, ip := range got {
			gotSet[ip.String()] = true
		}
		wantSet := map[string]bool{}
		for _, a := range want {
			ip := net.ParseIP(a).String()
			wantSet[ip] = true
			if !gotSet[ip] {
				res.Missing = append(res.Missing, ip)
			}
		}
		for ip := range gotSet {
			if !wantSet[ip] {
				res.Unexpected = append(res.Unexpected, ip)
			}
		}
		sort.Strings(res.Unexpected)
		res.OK = len(res.Missing) == 0 && len(res.Unexpected) == 0 && len(want) > 0
		out = append(out, res)
	}
	if label != "" && len(out) == 0 {
		return nil, fmt.Errorf("node %s: %w", label, ErrNotFound)
	}
	return out, nil
}
