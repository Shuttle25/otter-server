package netlog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	cases := []struct {
		err   error
		bytes int64
		want  Class
	}{
		{nil, 0, OK},
		{context.DeadlineExceeded, 0, Timeout},
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, 0, Timeout},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, 0, Refused},
		{&net.OpError{Op: "read", Err: syscall.ECONNRESET}, 0, Reset},
		{&net.OpError{Op: "read", Err: syscall.ECONNRESET}, 4096, ResetAfterKB},
		{io.ErrUnexpectedEOF, 2048, ResetAfterKB},
		{io.EOF, 10, Reset},
		{tls.AlertError(40), 0, TLS},
		{fmt.Errorf("x: %w", &tls.CertificateVerificationError{Err: errors.New("pin")}), 0, TLS},
		{fmt.Errorf("x: %w", ErrHandshake), 0, Handshake},
		{errors.New("something else"), 0, Reset},
	}
	for i, c := range cases {
		if got := Classify(c.err, c.bytes); got != c.want {
			t.Errorf("%d: Classify(%v, %d) = %s, want %s", i, c.err, c.bytes, got, c.want)
		}
	}
}
