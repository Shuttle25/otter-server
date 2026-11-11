// Package vectors produces cross-language test vectors (consumed by otter-android).
package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/admin"
	"ottermsg/server/internal/keys"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

type V1 struct {
	SeedHex                 string `json:"seed_hex"`
	AccountPubHex           string `json:"account_pub_hex"`
	UserIDHex               string `json:"user_id_hex"`
	NetworkSeedHex          string `json:"network_seed_hex"`
	NetworkPubHex           string `json:"network_pub_hex"`
	NetworkIDHex            string `json:"network_id_hex"`
	ManifestVersion         uint64 `json:"manifest_version"`
	ManifestRecordHex       string `json:"manifest_record_hex"`
	DirectoryEntryRecordHex string `json:"directory_entry_record_hex"`
	BadSignatureRecordHex   string `json:"bad_signature_record_hex"`
	IdentityPubHex          string `json:"identity_pub_hex"`
	AuthMessageHex          string `json:"auth_message_hex"`
	InviteLink              string `json:"invite_link"`
	TLSCertDERHex           string `json:"tls_cert_der_hex"`
	TLSSPKIPinHex           string `json:"tls_spki_pin_hex"`
}

func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func generate(t *testing.T) []byte {
	seed := seq(32, 0)
	acc, err := keys.DeriveAccountKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	accPub := acc.Public().(ed25519.PublicKey)
	netPriv := ed25519.NewKeyFromSeed(seq(32, 100))
	netPub := netPriv.Public().(ed25519.PublicKey)

	m := &pb.Manifest{Version: 7, IssuedMs: 1_800_000_000_000, NetworkPub: netPub, Nodes: []*pb.NodeInfo{{
		NodeId: keys.ID16(seq(32, 200)), NodePub: seq(32, 200), Label: "fi-1",
		Endpoints: []*pb.Endpoint{{Kind: pb.Endpoint_WSS, Host: "chat.example.org", Port: 443, Path: "/abc"}}}}}
	mp, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	mrec, _ := records.Sign(&pb.RecordBody{Id: seq(16, 1), Type: pb.RecordType_MANIFEST, Author: keys.ID16(netPub), CreatedMs: 1_800_000_000_000, Payload: mp}, netPriv)

	e := &pb.DirectoryEntry{UserId: keys.ID16(accPub), Username: "mama", DisplayName: "Мама", AccountPub: accPub,
		IdentityPub: append([]byte{5}, seq(32, 50)...), IdentitySig: seq(64, 0), Version: 1, CanInvite: true}
	ep, _ := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	drec, _ := records.Sign(&pb.RecordBody{Id: seq(16, 2), Type: pb.RecordType_DIRECTORY_ENTRY, Author: keys.ID16(accPub), CreatedMs: 1_800_000_000_000, Payload: ep}, acc)

	bad := proto.Clone(mrec).(*pb.Record)
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[0] ^= 0xFF

	enc := func(r *pb.Record) string { b, _ := proto.Marshal(r); return hex.EncodeToString(b) }
	v := V1{
		SeedHex: hex.EncodeToString(seed), AccountPubHex: hex.EncodeToString(accPub), UserIDHex: hex.EncodeToString(keys.ID16(accPub)),
		NetworkSeedHex: hex.EncodeToString(seq(32, 100)), NetworkPubHex: hex.EncodeToString(netPub), NetworkIDHex: hex.EncodeToString(keys.ID16(netPub)),
		ManifestVersion: 7, ManifestRecordHex: enc(mrec), DirectoryEntryRecordHex: enc(drec), BadSignatureRecordHex: enc(bad),
	}
	idPriv, err := hkdf.Key(sha256.New, seed, nil, "otter/identity/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	idPub, err := curve25519.X25519(idPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	v.IdentityPubHex = "05" + hex.EncodeToString(idPub)
	v.AuthMessageHex = hex.EncodeToString(keys.AuthMessage(seq(16, 10), seq(32, 20), 1_800_000_000_000))
	v.InviteLink, err = admin.EncodeInviteLink(&pb.InviteBundle{NetworkPub: netPub, Manifest: mrec, Secret: seq(32, 9),
		InviterUserId: keys.ID16(accPub), InviterAccountPub: accPub, InviterIdentityPub: append([]byte{5}, idPub...), InviterName: "Мама"})
	if err != nil {
		t.Fatal(err)
	}
	der := tlsCertDER(t)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	v.TLSCertDERHex = hex.EncodeToString(der)
	v.TLSSPKIPinHex = hex.EncodeToString(pinning.SPKIPin(cert))
	out, _ := json.MarshalIndent(v, "", "  ")
	return append(out, '\n')
}

func TestVectorsV1(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "vectors", "v1.json")
	got := generate(t)
	if os.Getenv("OTTER_WRITE_VECTORS") == "1" {
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing vectors (run with OTTER_WRITE_VECTORS=1): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("vectors changed: derivation or encoding drifted; regenerate only if intentional")
	}
}

// tlsCertDER returns the committed test certificate (created once, intentionally, with OTTER_WRITE_VECTORS=1).
func tlsCertDER(t *testing.T) []byte {
	path := filepath.Join("..", "..", "testdata", "vectors", "tls_cert.der")
	if _, err := os.Stat(path); os.IsNotExist(err) && os.Getenv("OTTER_WRITE_VECTORS") == "1" {
		certPEM, _, _, err := pinning.GenerateCert([]string{"node.example"}, nil, 10*365*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(certPEM)
		if err := os.WriteFile(path, b.Bytes, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	der, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing tls_cert.der (run with OTTER_WRITE_VECTORS=1): %v", err)
	}
	return der
}
