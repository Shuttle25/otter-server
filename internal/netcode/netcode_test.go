package netcode

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCodeVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/network_code.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		NetworkPub string `json:"network_pub"`
		Code       string `json:"code"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil || len(vs) != 3 {
		t.Fatalf("vectors: %v (%d)", err, len(vs))
	}
	for _, v := range vs {
		pub, _ := hex.DecodeString(v.NetworkPub)
		if got := Code(pub); got != v.Code {
			t.Errorf("Code(%s…) = %q, want %q", v.NetworkPub[:8], got, v.Code)
		}
	}
}
