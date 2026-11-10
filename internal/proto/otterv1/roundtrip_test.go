package otterv1_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/proto/otterv1"
)

func TestRecordRoundTrip(t *testing.T) {
	body := &otterv1.RecordBody{Id: make([]byte, 16), Type: otterv1.RecordType_MANIFEST, Author: make([]byte, 16), CreatedMs: 42}
	b, err := proto.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var got otterv1.RecordBody
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(body, &got) {
		t.Fatalf("mismatch: %v vs %v", body, &got)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m := &otterv1.Manifest{Version: 3, Nodes: []*otterv1.NodeInfo{{Label: "a", Endpoints: []*otterv1.Endpoint{{Kind: otterv1.Endpoint_WSS, Host: "x", Port: 443}}}}}
	b, _ := proto.Marshal(m)
	var got otterv1.Manifest
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(m, &got) {
		t.Fatal("mismatch")
	}
}
