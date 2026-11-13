package turnsrv

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TURN REST credentials are defined with HMAC-SHA1 (draft-uberti-behave-turn-rest)
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

// TTL of issued credentials (D77).
const TTL = 12 * time.Hour

// UserTag is the TURN user id: a short hash, so the TURN layer never sees the account id itself.
func UserTag(userID []byte) string {
	h := sha256.Sum256(userID)
	return hex.EncodeToString(h[:])[:16]
}

// Credentials returns TURN-REST credentials valid until now+ttl, only on the node holding secret.
func Credentials(secret, userID []byte, now time.Time, ttl time.Duration) (username, password string) {
	username = fmt.Sprintf("%d:%s", now.Add(ttl).Unix(), UserTag(userID))
	m := hmac.New(sha1.New, secret)
	m.Write([]byte(username))
	return username, base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// expired reports whether a TURN-REST username is past its expiry at now, or is not "<unix expiry>:<user>" at all.
// Same rule as pion (valid through the expiry second), but with our clock so tests can move it.
func expired(username string, now time.Time) bool {
	ts, user, ok := strings.Cut(username, ":")
	if !ok || user == "" {
		return true
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	return err != nil || t < 0 || t < now.Unix()
}

// Issuer answers turn.credentials for this node.
type Issuer struct {
	Secret                    []byte
	RelayIP                   string // public IP of the node (same as relay_ip)
	TLS                       bool   // a TLS listener runs on TLSPort
	UDPPort, TCPPort, TLSPort int
}

func (i Issuer) Issue(userID []byte, now time.Time) *pb.TurnCredentials {
	u, p := Credentials(i.Secret, userID, now, TTL)
	urls := []string{
		fmt.Sprintf("turn:%s:%d?transport=udp", i.RelayIP, i.UDPPort),
		fmt.Sprintf("turn:%s:%d?transport=tcp", i.RelayIP, i.TCPPort),
	}
	if i.TLS {
		urls = append(urls, fmt.Sprintf("turns:%s:%d?transport=tcp", i.RelayIP, i.TLSPort))
	}
	return &pb.TurnCredentials{Username: u, Password: p, TtlS: uint32(TTL / time.Second), Urls: urls}
}
