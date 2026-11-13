package otterv1

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestCallMessageRoundTrip(t *testing.T) {
	id := bytes.Repeat([]byte{7}, 16)
	in := &Content{SentMs: 5, Body: &Content_Call{Call: &CallMessage{CallId: id,
		Kind: &CallMessage_Offer{Offer: &CallOffer{Sdp: "v=0", Restart: true}}}}}
	raw, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Content
	if err := proto.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	c := out.GetCall()
	if !bytes.Equal(c.GetCallId(), id) || c.GetOffer().GetSdp() != "v=0" || !c.GetOffer().GetRestart() {
		t.Fatalf("round trip lost data: %v", &out)
	}
	h := &CallMessage{Kind: &CallMessage_Hangup{Hangup: &CallHangup{Reason: CallHangup_BUSY}}}
	if h.GetHangup().GetReason() != CallHangup_BUSY {
		t.Fatal("hangup reason")
	}
	if Status_STATUS_UNAVAILABLE != 9 {
		t.Fatal("STATUS_UNAVAILABLE must be 9")
	}
}
