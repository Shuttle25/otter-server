package admin

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

// RekeyInviteTTL is how long the invite for the new install of a re-keyed account is valid (D111).
const RekeyInviteTTL = 7 * 24 * time.Hour

var usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

// rekeyState is DIR/rekeys/<username>.json between the two steps (and <username>.done.json after them).
type rekeyState struct {
	Old        string `json:"old"`
	InviteID   string `json:"invite_id"`
	StartedMs  int64  `json:"started_ms"`
	New        string `json:"new,omitempty"`
	FinishedMs int64  `json:"finished_ms,omitempty"`
}

// RekeyStartResult holds the records of step 1: REVOCATION{old, "rekey"} and the invite for the new install.
type RekeyStartResult struct {
	Revocation *pb.Record
	Invite     *BootstrapResult
}

// ParseUserCode reads «Код аккаунта» as the app shows it: 32 hex digits; spaces and dashes are ignored.
func ParseUserCode(s string) ([]byte, error) {
	s = strings.NewReplacer(" ", "", "-", "", "\t", "", "\n", "", "\r", "").Replace(s)
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, errors.New("the account code is 32 hex digits (Settings → Профиль → «Код аккаунта»)")
	}
	return b, nil
}

func rekeyFile(dir, username string) string { return filepath.Join(dir, "rekeys", username+".json") }

// RekeyPending returns the old account of the re-key of username started on this machine.
func RekeyPending(dir, username string) ([]byte, error) {
	s, err := readRekey(dir, username)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(s.Old)
}

func readRekey(dir, username string) (*rekeyState, error) {
	if !usernameRe.MatchString(username) {
		return nil, fmt.Errorf("%q is not a username", username)
	}
	raw, err := os.ReadFile(rekeyFile(dir, username))
	if err != nil {
		return nil, fmt.Errorf("no re-key of %s started here (run 'user rekey %s --old CODE' first): %w", username, username, err)
	}
	var s rekeyState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", rekeyFile(dir, username), err)
	}
	if old, err := hex.DecodeString(s.Old); err != nil || len(old) != 16 {
		return nil, fmt.Errorf("%s: bad old account", rekeyFile(dir, username))
	}
	return &s, nil
}

// RekeyStart (D111 step 1) signs REVOCATION{old, "rekey"} and a network invite (7 days) for the new install. Nothing
// is recorded as started: the caller publishes both and then calls RekeyStarted. A pending re-key of username for
// another account is refused; the same account may be started again (a fresh invite).
func RekeyStart(dir string, priv ed25519.PrivateKey, username string, old []byte, now time.Time) (*RekeyStartResult, error) {
	if !usernameRe.MatchString(username) || len(old) != 16 {
		return nil, errors.New("usage: user rekey USERNAME --old CODE")
	}
	if s, err := readRekey(dir, username); err == nil && s.Old != hex.EncodeToString(old) {
		return nil, fmt.Errorf("a re-key of %s for account %s is already started: finish it with --new, or remove %s",
			username, s.Old, rekeyFile(dir, username))
	}
	rev, err := SignRevocation(dir, priv, old, "rekey", now)
	if err != nil {
		return nil, err
	}
	inv, err := NetworkInvite(dir, priv, now, RekeyInviteTTL)
	if err != nil {
		return nil, err
	}
	return &RekeyStartResult{Revocation: rev, Invite: inv}, nil
}

// RekeyStarted records step 1 as done in DIR/rekeys/<username>.json (0600).
func RekeyStarted(dir, username string, old, inviteID []byte, now time.Time) error {
	if err := os.MkdirAll(filepath.Join(dir, "rekeys"), 0o700); err != nil {
		return err
	}
	j, _ := json.MarshalIndent(rekeyState{Old: hex.EncodeToString(old), InviteID: hex.EncodeToString(inviteID),
		StartedMs: now.UnixMilli()}, "", "  ")
	return os.WriteFile(rekeyFile(dir, username), append(j, '\n'), 0o600)
}

// RekeyFinish (D111 step 2) signs REKEY{old, new} for the re-key of username started here; new is the code the
// person read from the new install. A copy is kept in DIR/rekeys/<old hex>.bin.
func RekeyFinish(dir string, priv ed25519.PrivateKey, username string, nw []byte, now time.Time) (*pb.Record, error) {
	s, err := readRekey(dir, username)
	if err != nil {
		return nil, err
	}
	old, _ := hex.DecodeString(s.Old)
	if len(nw) != 16 {
		return nil, errors.New("the new account code is 32 hex digits")
	}
	if bytes.Equal(old, nw) {
		return nil, errors.New("the new account code is the lost account's: ask for the code shown by the new install")
	}
	return signNetwork(dir, "rekeys", priv, pb.RecordType_REKEY, old, &pb.Rekey{OldUserId: old, NewUserId: nw}, now)
}

// RekeyDone marks the re-key of username finished: <username>.json becomes <username>.done.json with the new account.
func RekeyDone(dir, username string, nw []byte, now time.Time) error {
	s, err := readRekey(dir, username)
	if err != nil {
		return err
	}
	s.New, s.FinishedMs = hex.EncodeToString(nw), now.UnixMilli()
	j, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "rekeys", username+".done.json"), append(j, '\n'), 0o600); err != nil {
		return err
	}
	return os.Remove(rekeyFile(dir, username))
}
