// Package records signs and validates replicated records. It performs no I/O.
package records

import (
	"crypto/ed25519"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

// v2Prefix starts every v2 signed message (D109); the NUL keeps it from being a prefix of a valid protobuf body.
const v2Prefix = "otter-v2\x00"

// SigContext says how a signer signs new records (D109).
type SigContext struct {
	NetworkID []byte // keys.ID16(network_pub), 16 bytes
	V2        bool   // sign v2: the newest manifest has sig_v1_until_ms != 0
}

// ContextFor is the signing context implied by manifest m of the network networkPub (m may be nil).
func ContextFor(networkPub ed25519.PublicKey, m *pb.Manifest) SigContext {
	return SigContext{NetworkID: keys.ID16(networkPub), V2: m.GetSigV1UntilMs() != 0}
}

// MessageV2 is the byte string a v2 signature covers: "otter-v2\x00" ‖ network_id ‖ body.
func MessageV2(networkID, body []byte) []byte {
	m := make([]byte, 0, len(v2Prefix)+len(networkID)+len(body))
	m = append(m, v2Prefix...)
	m = append(m, networkID...)
	return append(m, body...)
}

// Sign serializes body deterministically and signs the exact bytes (v1). Kept for tests and pre-cut-over tooling;
// production signers use SignWith.
func Sign(body *pb.RecordBody, priv ed25519.PrivateKey) (*pb.Record, error) {
	return SignWith(body, priv, SigContext{})
}

// SignWith signs v2 when sc.V2, else v1.
func SignWith(body *pb.RecordBody, priv ed25519.PrivateKey, sc SigContext) (*pb.Record, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	msg := b
	if sc.V2 {
		msg = MessageV2(sc.NetworkID, b)
	}
	return &pb.Record{Body: b, Signature: ed25519.Sign(priv, msg)}, nil
}

// VerifySig accepts a v2 signature for the network networkID, or a v1 signature (body only) for a record created
// before the cut-over v1Until (0 = no cut-over: v1 is valid for every record) (D109).
func VerifySig(key ed25519.PublicKey, networkID, body, sig []byte, createdMs, v1Until int64) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	if ed25519.Verify(key, MessageV2(networkID, body), sig) {
		return true
	}
	return (v1Until == 0 || createdMs < v1Until) && ed25519.Verify(key, body, sig)
}
