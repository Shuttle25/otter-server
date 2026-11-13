package turnsrv

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func quietLogger() logging.LeveledLogger {
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	return lf.NewLogger("t")
}

func TestCredentialsFormat(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, SecretLen)
	user := bytes.Repeat([]byte{9}, 16)
	u, p := Credentials(secret, user, time.Unix(1_800_000_000, 0), 12*time.Hour)
	tag := strings.SplitN(u, ":", 2)[1]
	if !strings.HasPrefix(u, "1800043200:") || len(tag) != 16 || tag != UserTag(user) {
		t.Fatalf("username %q", u)
	}
	if strings.Contains(u, string(user)) || p == "" {
		t.Fatalf("username must not carry the account id: %q", u)
	}
	u2, _ := Credentials(secret, bytes.Repeat([]byte{8}, 16), time.Unix(1_800_000_000, 0), 12*time.Hour)
	if u2 == u {
		t.Fatal("different users must get different tags")
	}
}

func TestCredentialsAcceptedByPion(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, SecretLen)
	user := bytes.Repeat([]byte{9}, 16)
	h := turn.LongTermTURNRESTAuthHandler(string(secret), quietLogger())
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 5000}
	// pion compares the expiry with the real clock: use a username that expires in the future
	u, p := Credentials(secret, user, time.Now(), time.Hour)
	id, key, ok := h(&turn.RequestAttributes{Username: u, Realm: "otter", SrcAddr: src})
	if !ok || !bytes.Equal(key, turn.GenerateAuthKey(u, "otter", p)) {
		t.Fatal("pion rejected our credentials")
	}
	if id != UserTag(user) {
		t.Fatalf("pion user id %q, want the tag", id)
	}
	other := bytes.Repeat([]byte{2}, SecretLen)
	h2 := turn.LongTermTURNRESTAuthHandler(string(other), quietLogger())
	if _, key2, ok := h2(&turn.RequestAttributes{Username: u, Realm: "otter", SrcAddr: src}); ok && bytes.Equal(key2, key) {
		t.Fatal("another node's secret must not produce the same key")
	}
	old, _ := Credentials(secret, user, time.Now().Add(-2*time.Hour), time.Hour)
	if _, _, ok := h(&turn.RequestAttributes{Username: old, Realm: "otter", SrcAddr: src}); ok {
		t.Fatal("expired username accepted")
	}
}

func TestExpired(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for name, want := range map[string]bool{
		"1800000001:abcd": false,
		"1800000000:abcd": false, // the expiry second itself is still valid (pion: t < now)
		"1799999999:abcd": true,
		"abc:abcd":        true,
		":abcd":           true,
		"":                true,
		"-1:abcd":         true,
		"1800000001":      true, // no user part: not ours
	} {
		if got := expired(name, now); got != want {
			t.Errorf("%q: expired=%v want %v", name, got, want)
		}
	}
}

func TestIssuerURLs(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, SecretLen)
	i := Issuer{Secret: secret, RelayIP: "203.0.113.7", UDPPort: 3478, TCPPort: 3478, TLSPort: 5349}
	c := i.Issue([]byte("anna"), time.Unix(1_800_000_000, 0))
	if c.TtlS != 43200 || len(c.Urls) != 2 ||
		c.Urls[0] != "turn:203.0.113.7:3478?transport=udp" || c.Urls[1] != "turn:203.0.113.7:3478?transport=tcp" {
		t.Fatalf("%+v", c)
	}
	if u, p := Credentials(secret, []byte("anna"), time.Unix(1_800_000_000, 0), TTL); c.Username != u || c.Password != p {
		t.Fatal("issuer must hand out Credentials()")
	}
	i.TLS = true
	c = i.Issue([]byte("anna"), time.Unix(1_800_000_000, 0))
	if len(c.Urls) != 3 || c.Urls[2] != "turns:203.0.113.7:5349?transport=tcp" {
		t.Fatalf("%v", c.Urls)
	}
}
