// Package records signs and validates replicated records. It performs no I/O.
package records

import (
	"crypto/ed25519"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

// Sign serializes body deterministically and signs the exact bytes.
func Sign(body *pb.RecordBody, priv ed25519.PrivateKey) (*pb.Record, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &pb.Record{Body: b, Signature: ed25519.Sign(priv, b)}, nil
}
