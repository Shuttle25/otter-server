package limits

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestKeyedBucket(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	k := NewKeyed(1, 3) // 1/s, burst 3
	k.Now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !k.Allow("a") {
			t.Fatalf("burst %d refused", i)
		}
	}
	if k.Allow("a") {
		t.Fatal("4th within the same second allowed")
	}
	if !k.Allow("b") {
		t.Fatal("another key shares the bucket")
	}
	now = now.Add(time.Second)
	if !k.Allow("a") {
		t.Fatal("refill after 1 s")
	}
	if !k.Allow("") {
		t.Fatal("empty key must be exempt")
	}
	var nilK *Keyed
	if !nilK.Allow("a") {
		t.Fatal("nil limiter must allow")
	}
	// idle buckets are forgotten after 10 min (they would be full again anyway)
	now = now.Add(11 * time.Minute)
	k.Allow("c")
	k.mu.Lock()
	n := len(k.m)
	k.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d buckets kept after 11 min idle", n)
	}
}

func TestClientIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7:4000":           "203.0.113.7",
		"[2001:db8:1:2:3:4:5:6]:443": "2001:db8:1:2::/64", // one phone = one /64 (D105)
		"[2001:db8:1:2:ffff::9]:443": "2001:db8:1:2::/64",
		"[::ffff:203.0.113.8]:1":     "203.0.113.8",
		"127.0.0.1:5000":             "127.0.0.1",
		"[::1]:5000":                 "::1",
		"tunnel:00112233":            "tunnel:00112233", // restore relayed by a peer: the relay's source (D105)
		"garbage":                    "",
		"":                           "",
	} {
		if got := Source(in); got != want {
			t.Errorf("Source(%q) = %q, want %q", in, got, want)
		}
	}
	if !IsLoopback("127.0.0.1") || !IsLoopback("::1") || IsLoopback("203.0.113.7") || IsLoopback("tunnel:00") {
		t.Fatal("IsLoopback")
	}
}

// A hostile client opens more parallel connections than allowed.
func TestConnsPerIP(t *testing.T) {
	release := make(chan struct{})
	var started sync.WaitGroup
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { started.Done(); <-release })
	c := &Conns{PerIP: 2, Rate: NewKeyed(100, 100), Count: &Counters{}}
	wrapped := c.Wrap(h)
	req := func(addr string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, r)
		return w
	}
	started.Add(2)
	done := make(chan struct{}, 3)
	for i := 0; i < 2; i++ {
		go func() { req("203.0.113.7:4000"); done <- struct{}{} }()
	}
	started.Wait()
	if w := req("203.0.113.7:4001"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd concurrent: %d", w.Code)
	}
	if c.Count.ConnIP.Load() != 1 {
		t.Fatalf("counter %d", c.Count.ConnIP.Load())
	}
	// another address is not affected
	started.Add(1)
	go func() { req("203.0.113.9:4000"); done <- struct{}{} }()
	started.Wait()
	close(release)
	<-done
	<-done
	<-done
	started.Add(1) // the next request's handler signals once; release is closed, so it returns at once
	if w := req("203.0.113.7:4002"); w.Code == http.StatusTooManyRequests {
		t.Fatal("slot not freed")
	}
	// loopback (REALITY's inner listener) is exempt when asked
	c2 := &Conns{PerIP: 0, Rate: NewKeyed(0.0001, 0), Count: &Counters{}, ExemptLoopback: true}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	w := httptest.NewRecorder()
	c2.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("loopback: %d", w.Code)
	}
}

// A hostile client opens new connections faster than allowed: the burst passes, then 429 until the rate refills.
func TestConnsNewPerMinute(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rate := NewKeyed(30.0/60, 20) // D116
	rate.Now = func() time.Time { return now }
	c := &Conns{PerIP: 32, Rate: rate, Count: &Counters{}}
	h := c.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	code := func(addr string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 20; i++ {
		if got := code("203.0.113.7:1"); got != 204 {
			t.Fatalf("new connection %d refused: %d", i, got)
		}
	}
	if got := code("203.0.113.7:1"); got != http.StatusTooManyRequests {
		t.Fatalf("21st new connection within a second: %d", got)
	}
	if c.Count.ConnRate.Load() != 1 {
		t.Fatalf("counter %d", c.Count.ConnRate.Load())
	}
	if got := code("203.0.113.8:1"); got != 204 {
		t.Fatalf("other address: %d", got)
	}
	now = now.Add(2 * time.Second) // 30/min = one every 2 s
	if got := code("203.0.113.7:1"); got != 204 {
		t.Fatalf("after refill: %d", got)
	}
	m := c.Count.Map()
	if m["conn_rate"] != 1 || len(m) != 7 {
		t.Fatalf("map %v", m)
	}
}
