package store

import (
	"context"
	"testing"
)

func TestStats(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st != (Stats{}) {
		t.Fatalf("empty store: %+v", st)
	}
	r, b := rec(t)
	if _, _, err := s.Apply(ctx, r, b); err != nil {
		t.Fatal(err)
	}
	st, err = s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Records != 1 || st.OplogSeq < 1 {
		t.Fatalf("after one record: %+v", st)
	}
}
