// Package limits: token buckets per key and per-IP connection limits (D116).
package limits

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Keyed holds one token bucket per key (an IP, a user id). nil or key "" allows everything.
type Keyed struct {
	Rate, Burst float64 // tokens per second, bucket size
	Now         func() time.Time
	mu          sync.Mutex
	m           map[string]*bucket
	swept       time.Time
}

func NewKeyed(perSec, burst float64) *Keyed {
	return &Keyed{Rate: perSec, Burst: burst, m: map[string]*bucket{}}
}

// Allow takes one token from key's bucket; false = over the rate.
func (k *Keyed) Allow(key string) bool {
	if k == nil || key == "" {
		return true
	}
	now := time.Now()
	if k.Now != nil {
		now = k.Now()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]*bucket{}
	}
	if now.Sub(k.swept) > time.Minute { // idle buckets are full again: forget them
		for key, b := range k.m {
			if now.Sub(b.last) > 10*time.Minute {
				delete(k.m, key)
			}
		}
		k.swept = now
	}
	b := k.m[key]
	if b == nil {
		b = &bucket{tokens: k.Burst, last: now}
		k.m[key] = b
	} else {
		b.tokens = min(k.Burst, b.tokens+now.Sub(b.last).Seconds()*k.Rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Counters count refusals per kind (otter_rejected_total{kind}, see Map for the kind names).
type Counters struct {
	ConnIP, ConnRate, ReqRate, PublicRate, UserRate, Pending, Disk atomic.Int64
}

// Map returns the counters by kind name, as monitoring exports them.
func (c *Counters) Map() map[string]int64 {
	return map[string]int64{"conn_ip": c.ConnIP.Load(), "conn_rate": c.ConnRate.Load(), "req_rate": c.ReqRate.Load(),
		"public_rate": c.PublicRate.Load(), "user_rate": c.UserRate.Load(), "pending": c.Pending.Load(), "disk": c.Disk.Load()}
}

// Source is the limit key of a remote address: the IPv4 address, the IPv6 /64 (one phone or home network, as the
// restore limit D105), a loopback address unchanged, a relayed restore stream's "tunnel:<node id>" unchanged (all
// restores relayed by one node share it, D105), "" if unparsable. No forwarding header is ever trusted.
func Source(remoteAddr string) string {
	if strings.HasPrefix(remoteAddr, "tunnel:") {
		return remoteAddr
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return ""
	case ip.IsLoopback():
		return ip.String()
	case ip.To4() != nil:
		return ip.To4().String()
	}
	m := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: ip.Mask(m), Mask: m}).String()
}

// ClientIP is the request's limit key (Source of its remote address).
func ClientIP(r *http.Request) string { return Source(r.RemoteAddr) }

// IsLoopback reports whether a key from Source is a loopback address.
func IsLoopback(ip string) bool { p := net.ParseIP(ip); return p != nil && p.IsLoopback() }

// Conns limits concurrent and new requests (each WebSocket is one long request) per source IP.
type Conns struct {
	PerIP          int
	Rate           *Keyed
	Count          *Counters
	ExemptLoopback bool // REALITY's inner listener forwards from 127.0.0.1
	mu             sync.Mutex
	open           map[string]int
}

func (c *Conns) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if ip == "" || (c.ExemptLoopback && IsLoopback(ip)) {
			h.ServeHTTP(w, r)
			return
		}
		if !c.Rate.Allow(ip) {
			c.Count.ConnRate.Add(1)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		c.mu.Lock()
		if c.open == nil {
			c.open = map[string]int{}
		}
		if c.open[ip] >= c.PerIP {
			c.mu.Unlock()
			c.Count.ConnIP.Add(1)
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		c.open[ip]++
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			if c.open[ip]--; c.open[ip] <= 0 {
				delete(c.open, ip)
			}
			c.mu.Unlock()
		}()
		h.ServeHTTP(w, r)
	})
}
