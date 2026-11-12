package push

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeFCM serves an OAuth token endpoint and messages:send; status decides the send answer.
type fakeFCM struct {
	mu     sync.Mutex
	srv    *httptest.Server
	status int
	body   string
	sent   []map[string]any
	auth   []string
}

func newFakeFCM(t *testing.T) *fakeFCM {
	f := &fakeFCM{status: 200, body: `{"name":"projects/p/messages/1"}`}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"fake-access","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/v1/projects/test-project/messages:send", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		f.mu.Lock()
		f.sent = append(f.sent, m)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		st, body := f.status, f.body
		f.mu.Unlock()
		w.WriteHeader(st)
		io.WriteString(w, body)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// set changes the answer of messages:send.
func (f *fakeFCM) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

// serviceAccount returns a throwaway service-account key whose token_uri points at the fake server.
func serviceAccount(t *testing.T, tokenURI string) []byte {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "test-project",
		"private_key_id": "k1", "private_key": pemKey, "client_email": "otter@test-project.iam.gserviceaccount.com",
		"token_uri": tokenURI})
	return b
}

func TestFCMSend(t *testing.T) {
	f := newFakeFCM(t)
	c, err := NewFCM(serviceAccount(t, f.srv.URL+"/token"), WithBaseURL(f.srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if c.ProjectID() != "test-project" {
		t.Fatalf("project: %q", c.ProjectID())
	}
	if err := c.Send(context.Background(), "device-token"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) != 1 || f.auth[0] != "Bearer fake-access" {
		t.Fatalf("sent %v auth %v", f.sent, f.auth)
	}
	msg := f.sent[0]["message"].(map[string]any)
	android := msg["android"].(map[string]any)
	data := msg["data"].(map[string]any)
	if msg["token"] != "device-token" || android["priority"] != "HIGH" || android["collapse_key"] != "otter" ||
		android["ttl"] != "600s" || len(data) != 1 || data["w"] != "1" || msg["notification"] != nil {
		t.Fatalf("message: %v", msg)
	}
}

func TestFCMErrors(t *testing.T) {
	f := newFakeFCM(t)
	c, _ := NewFCM(serviceAccount(t, f.srv.URL+"/token"), WithBaseURL(f.srv.URL))
	f.set(404, `{"error":{"code":404,"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`)
	if err := c.Send(context.Background(), "gone"); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("404: %v", err)
	}
	f.set(400, `{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"errorCode":"UNREGISTERED"}]}}`)
	if err := c.Send(context.Background(), "gone"); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("UNREGISTERED code: %v", err)
	}
	f.set(503, `{"error":{"code":503,"status":"UNAVAILABLE"}}`)
	if err := c.Send(context.Background(), "x"); err == nil || errors.Is(err, ErrUnregistered) || !strings.Contains(err.Error(), "503") {
		t.Fatalf("503: %v", err)
	}
	if _, err := NewFCM([]byte(`{"type":"service_account"}`)); err == nil {
		t.Fatal("key without project_id accepted")
	}
}
