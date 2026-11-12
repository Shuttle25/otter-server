package store

import (
	"context"
	"crypto/rand"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

func newsItem(t *testing.T, typ pb.RecordType, author []byte, created int64, payload proto.Message) (*pb.Record, *pb.RecordBody) {
	t.Helper()
	p, _ := proto.Marshal(payload)
	id := make([]byte, 16)
	rand.Read(id)
	b := &pb.RecordBody{Id: id, Type: typ, Author: author, CreatedMs: created, Payload: p}
	raw, _ := proto.Marshal(b)
	return &pb.Record{Body: raw, Signature: make([]byte, 64)}, b
}

func key(b *pb.RecordBody) []byte { return append(append([]byte{}, b.Author...), b.Id...) }

// newsBodies parses the records News returns.
func newsBodies(t *testing.T, raws [][]byte) []*pb.RecordBody {
	t.Helper()
	var out []*pb.RecordBody
	for _, raw := range raws {
		var r pb.Record
		var b pb.RecordBody
		if err := proto.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(r.Body, &b); err != nil {
			t.Fatal(err)
		}
		out = append(out, &b)
	}
	return out
}

func TestNewsStoreAndDelete(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a1 := make([]byte, 16)
	rand.Read(a1)
	r2, b2 := newsItem(t, pb.RecordType_ANNOUNCEMENT, a1, 2000, &pb.Announcement{TextRu: "два"})
	r1, b1 := newsItem(t, pb.RecordType_ANNOUNCEMENT, a1, 1000, &pb.Announcement{TextRu: "один"})
	for _, x := range []struct {
		r *pb.Record
		b *pb.RecordBody
	}{{r2, b2}, {r1, b1}} {
		if _, ok, err := s.Apply(ctx, x.r, x.b); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	got, err := s.News(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("News: %d %v", len(got), err)
	}
	if bs := newsBodies(t, got); bs[0].CreatedMs != 1000 || bs[1].CreatedMs != 2000 {
		t.Fatalf("not oldest first: %d %d", bs[0].CreatedMs, bs[1].CreatedMs)
	}
	// delete the first after it arrived
	rd, bd := newsItem(t, pb.RecordType_ANNOUNCEMENT_DELETED, a1, 3000, &pb.AnnouncementDeleted{Target: key(b1)})
	if _, _, err := s.Apply(ctx, rd, bd); err != nil {
		t.Fatal(err)
	}
	got, _ = s.News(ctx)
	if len(got) != 2 { // announcement two + the deletion record
		t.Fatalf("after delete: %d", len(got))
	}
	// a deletion that arrives before its announcement
	r3, b3 := newsItem(t, pb.RecordType_ANNOUNCEMENT, a1, 4000, &pb.Announcement{TextRu: "три"})
	rd3, bd3 := newsItem(t, pb.RecordType_ANNOUNCEMENT_DELETED, a1, 5000, &pb.AnnouncementDeleted{Target: key(b3)})
	if _, _, err := s.Apply(ctx, rd3, bd3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ApplyReplicated(ctx, r3, b3, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.News(ctx)
	if len(got) != 3 { // two + both deletions
		t.Fatalf("after early delete: %d", len(got))
	}
	for _, b := range newsBodies(t, got) {
		if b.Type == pb.RecordType_ANNOUNCEMENT && (string(key(b)) == string(key(b1)) || string(key(b)) == string(key(b3))) {
			t.Fatalf("deleted announcement still listed")
		}
	}
	if _, err := s.Get(ctx, key(b3)); err != ErrNotFound {
		t.Fatalf("deleted announcement still stored: %v", err)
	}
}

func TestNewsNotExpiring(t *testing.T) {
	for _, typ := range []pb.RecordType{pb.RecordType_ANNOUNCEMENT, pb.RecordType_ANNOUNCEMENT_DELETED} {
		if expiring(&pb.RecordBody{Type: typ}) {
			t.Errorf("%v expiring", typ)
		}
	}
}

func TestNewsDropExcept(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	keep, gone := make([]byte, 16), make([]byte, 16)
	rand.Read(keep)
	rand.Read(gone)
	for _, a := range [][]byte{keep, gone} {
		r, b := newsItem(t, pb.RecordType_ANNOUNCEMENT, a, 1000, &pb.Announcement{TextRu: "x"})
		if _, _, err := s.Apply(ctx, r, b); err != nil {
			t.Fatal(err)
		}
	}
	rd, bd := newsItem(t, pb.RecordType_ANNOUNCEMENT_DELETED, gone, 2000, &pb.AnnouncementDeleted{Target: make([]byte, 32)})
	if _, _, err := s.Apply(ctx, rd, bd); err != nil {
		t.Fatal(err)
	}
	n, err := s.DropNewsExcept(ctx, [][]byte{keep})
	if err != nil || n != 2 {
		t.Fatalf("drop: %d %v", n, err)
	}
	if got, _ := s.News(ctx); len(got) != 1 || string(newsBodies(t, got)[0].Author) != string(keep) {
		t.Fatalf("left: %d", len(got))
	}
	if n, _ := s.DropNewsExcept(ctx, nil); n != 1 {
		t.Fatalf("drop all: %d", n)
	}
	if got, _ := s.News(ctx); len(got) != 0 {
		t.Fatalf("left after drop all: %d", len(got))
	}
}

func TestNewsPushTargets(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if got, err := s.PushTargets(ctx); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	u := make([]byte, 16)
	rand.Read(u)
	r, b := newsItem(t, pb.RecordType_PUSH_TOKEN, u, 1000, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: "t"})
	if _, _, err := s.Apply(ctx, r, b); err != nil {
		t.Fatal(err)
	}
	got, err := s.PushTargets(ctx)
	if err != nil || len(got) != 1 || string(got[0].User) != string(u) || got[0].Device != 1 {
		t.Fatalf("%v %v", got, err)
	}
}
