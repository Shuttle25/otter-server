// Package netlog classifies connection outcomes for the connectivity log and endpoint demotion (D73, D74).
package netlog

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
)

type Class string

const (
	OK           Class = "ok"
	Timeout      Class = "timeout"
	Refused      Class = "refused"
	Reset        Class = "reset"          // dropped before any useful data
	ResetAfterKB Class = "reset_after_kb" // dropped after ≥ 1 KB: typical throttling
	TLS          Class = "tls"            // alert, bad certificate, pin mismatch
	Handshake    Class = "handshake"      // transport worked, the node handshake failed
)

// ThrottleBytes is the minimum received before a reset counts as throttling.
const ThrottleBytes = 1024

// ErrHandshake wraps node-handshake failures so they classify as Handshake.
var ErrHandshake = errors.New("node handshake failed")

// Classify maps a connection error and the bytes received before it to a failure class.
func Classify(err error, bytesIn int64) Class {
	if err == nil {
		return OK
	}
	if errors.Is(err, ErrHandshake) {
		return Handshake
	}
	var alert tls.AlertError
	var verr *tls.CertificateVerificationError
	var rec tls.RecordHeaderError
	if errors.As(err, &alert) || errors.As(err, &verr) || errors.As(err, &rec) {
		return TLS
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return Refused
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return Timeout
	}
	if bytesIn >= ThrottleBytes {
		return ResetAfterKB
	}
	// EOF, ECONNRESET and anything unknown before data: a plain reset.
	return Reset
}

// Entry is one log observation; the store merges repeats.
type Entry struct {
	Peer, Endpoint, Direction, Result, Detail string
	Class                                     Class
}

// Logger records observations; implementations must not block for long.
type Logger interface {
	Add(ctx context.Context, e Entry)
}

// Nop discards everything (tests, commands without a store).
type Nop struct{}

func (Nop) Add(context.Context, Entry) {}

// Result is "ok" or "fail" for a class.
func Result(c Class) string {
	if c == OK {
		return "ok"
	}
	return "fail"
}
