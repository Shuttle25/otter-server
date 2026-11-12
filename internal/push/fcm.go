// Package push sends data-less FCM wake-ups (D58/D59).
package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2/google"
)

// ErrUnregistered means FCM no longer knows the token: forget it.
var ErrUnregistered = errors.New("push token unregistered")

const scope = "https://www.googleapis.com/auth/firebase.messaging"

// FCM is a Firebase Cloud Messaging HTTP v1 sender authenticated by a service-account key.
type FCM struct {
	project  string
	endpoint string
	hc       *http.Client
}

type options struct{ base string }

// Option configures NewFCM (tests only).
type Option func(*options)

// WithBaseURL replaces https://fcm.googleapis.com (tests only).
func WithBaseURL(u string) Option { return func(o *options) { o.base = u } }

// NewFCM parses a Firebase service-account key. No network access until the first Send.
func NewFCM(credsJSON []byte, opts ...Option) (*FCM, error) {
	o := options{base: "https://fcm.googleapis.com"}
	for _, f := range opts {
		f(&o)
	}
	var meta struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(credsJSON, &meta); err != nil || meta.ProjectID == "" {
		return nil, errors.New("fcm credentials: not a service-account key with project_id")
	}
	cfg, err := google.JWTConfigFromJSON(credsJSON, scope)
	if err != nil {
		return nil, fmt.Errorf("fcm credentials: %w", err)
	}
	hc := cfg.Client(context.Background())
	hc.Timeout = 15 * time.Second
	return &FCM{project: meta.ProjectID, hc: hc,
		endpoint: fmt.Sprintf("%s/v1/projects/%s/messages:send", o.base, meta.ProjectID)}, nil
}

// ProjectID is the Firebase project named in the key file.
func (f *FCM) ProjectID() string { return f.project }

// Send delivers one constant, content-free, high-priority data message (D59).
func (f *FCM) Send(ctx context.Context, token string) error {
	body, _ := json.Marshal(map[string]any{"message": map[string]any{
		"token":   token,
		"android": map[string]any{"priority": "HIGH", "collapse_key": "otter", "ttl": "600s"},
		"data":    map[string]string{"w": "1"},
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.hc.Do(req)
	if err != nil {
		return fmt.Errorf("fcm: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	if resp.StatusCode == http.StatusNotFound {
		return ErrUnregistered
	}
	for _, d := range e.Error.Details {
		if d.ErrorCode == "UNREGISTERED" {
			return ErrUnregistered
		}
	}
	return fmt.Errorf("fcm: HTTP %d %s", resp.StatusCode, e.Error.Status)
}
