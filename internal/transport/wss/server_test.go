package wss

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouting(t *testing.T) {
	ws := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })
	peer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(298) })
	srv := httptest.NewServer(NewServer(Config{Path: "/s3cretPath"}, ws, peer).Handler)
	defer srv.Close()
	for path, want := range map[string]int{"/s3cretPath": 299, "/s3cretPath/peer": 298, "/": 404, "/s3cretPath/x": 404, "/other": 404, "/peer": 404} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
	}
}
