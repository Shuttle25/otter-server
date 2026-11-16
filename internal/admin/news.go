package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// keyringService is the Secret Service "service" attribute of the news key (D65).
const keyringService = "ottermsg-news"

func fmtHex(b []byte) string { return hex.EncodeToString(b) }

func keyringAccount(st *State) string { return "network-" + hex.EncodeToString(st.NetworkPub[:8]) }

// LoadNewsKeys reads news_keys.json (missing file = no keys).
func LoadNewsKeys(dir string) ([][]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, "news_keys.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hexes []string
	if err := json.Unmarshal(b, &hexes); err != nil {
		return nil, fmt.Errorf("news_keys.json: %w", err)
	}
	var out [][]byte
	for _, h := range hexes {
		k, err := hex.DecodeString(h)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("news_keys.json: bad key %q", h)
		}
		out = append(out, k)
	}
	return out, nil
}

func saveNewsKeys(dir string, ks [][]byte) error {
	hexes := []string{}
	for _, k := range ks {
		hexes = append(hexes, fmtHex(k))
	}
	b, _ := json.MarshalIndent(hexes, "", "  ")
	return os.WriteFile(filepath.Join(dir, "news_keys.json"), append(b, '\n'), 0o644)
}

// NewsInit creates the news key in the desktop keyring and lists its public key in news_keys.json (D65).
func NewsInit(dir string) (ed25519.PublicKey, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	if _, err := keyring.Get(keyringService, keyringAccount(st)); err == nil {
		return nil, fmt.Errorf("news key in the keyring: %w", ErrExists)
	} else if !errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("desktop keyring unavailable (is the session unlocked?): %w", err)
	}
	ks, err := LoadNewsKeys(dir)
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := keyring.Set(keyringService, keyringAccount(st), base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		return nil, fmt.Errorf("desktop keyring: %w", err)
	}
	return pub, saveNewsKeys(dir, append(ks, pub))
}

// newsKey loads the keyring key and checks it is still listed in news_keys.json.
func newsKey(dir string) (*State, ed25519.PrivateKey, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, nil, err
	}
	s, err := keyring.Get(keyringService, keyringAccount(st))
	if err != nil {
		return nil, nil, fmt.Errorf("no news key in this keyring (run 'news init'): %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, errors.New("keyring: corrupt news key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	ks, err := LoadNewsKeys(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, k := range ks {
		if bytes.Equal(k, priv.Public().(ed25519.PublicKey)) {
			return st, priv, nil
		}
	}
	return nil, nil, errors.New("the keyring news key is not in news_keys.json (revoked?)")
}

// LocalNewsKey returns the public key held in this keyring (if still listed), or nil.
func LocalNewsKey(dir string) ed25519.PublicKey {
	if _, priv, err := newsKey(dir); err == nil {
		return priv.Public().(ed25519.PublicKey)
	}
	return nil
}

// NewsRevoke removes a key from news_keys.json and, if it is the local one, from the keyring.
// The next 'manifest sign' + 'manifest publish' makes nodes and phones drop what it signed.
func NewsRevoke(dir, pubHex string) error {
	pubHex = strings.ToLower(strings.TrimSpace(pubHex))
	ks, err := LoadNewsKeys(dir)
	if err != nil {
		return err
	}
	var keep [][]byte
	found := false
	for _, k := range ks {
		if fmtHex(k) == pubHex {
			found = true
			continue
		}
		keep = append(keep, k)
	}
	if !found {
		return fmt.Errorf("news key %s: %w", pubHex, ErrNotFound)
	}
	if local := LocalNewsKey(dir); local != nil && fmtHex(local) == pubHex {
		st, err := LoadState(dir)
		if err != nil {
			return err
		}
		if err := keyring.Delete(keyringService, keyringAccount(st)); err != nil {
			return fmt.Errorf("desktop keyring: %w", err)
		}
	}
	return saveNewsKeys(dir, keep)
}

type oneNewsKey struct{ pub ed25519.PublicKey }

func (o oneNewsKey) NewsKey(id []byte) (ed25519.PublicKey, bool) {
	return o.pub, bytes.Equal(id, keys.ID16(o.pub))
}

// signNews signs a news record with the keyring key and checks it the way a node will.
func signNews(dir string, typ pb.RecordType, payload proto.Message, now time.Time) (*pb.Record, error) {
	st, priv, err := newsKey(dir)
	if err != nil {
		return nil, err
	}
	p, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	pub := priv.Public().(ed25519.PublicKey)
	rec, err := records.SignWith(&pb.RecordBody{Id: id, Type: typ, Author: keys.ID16(pub), CreatedMs: now.UnixMilli(), Payload: p}, priv,
		adminSig(st, dir))
	if err != nil {
		return nil, err
	}
	v := &records.Validator{NetworkPub: st.NetworkPub, News: oneNewsKey{pub}, Now: func() time.Time { return now },
		V1Until: func() int64 { return SigV1Until(dir) }}
	if _, err := v.Validate(rec); err != nil {
		return nil, fmt.Errorf("invalid news record (texts ≤ %d characters, at least one non-blank): %w", records.MaxNewsText, err)
	}
	return rec, nil
}

// RecordKeyHex is hex(author‖id), the record key nodes and phones use (and the announcement id).
func RecordKeyHex(rec *pb.Record) string {
	var b pb.RecordBody
	_ = proto.Unmarshal(rec.Body, &b)
	return fmtHex(append(append([]byte{}, b.Author...), b.Id...))
}

// NewsID is hex(id) of a news record: the id 'announce' prints and '--delete' takes a prefix of. The record key
// author‖id cannot serve, because every record of one news key starts with the same author.
func NewsID(rec *pb.Record) string {
	var b pb.RecordBody
	_ = proto.Unmarshal(rec.Body, &b)
	return fmtHex(b.Id)
}

// sentFile is where a signed news record is kept: DIR/news/<announcement key>.bin, or .del for its deletion.
func sentFile(dir string, rec *pb.Record) string {
	var b pb.RecordBody
	_ = proto.Unmarshal(rec.Body, &b)
	if b.Type == pb.RecordType_ANNOUNCEMENT_DELETED {
		var d pb.AnnouncementDeleted
		_ = proto.Unmarshal(b.Payload, &d)
		return filepath.Join(dir, "news", fmtHex(d.Target)+".del")
	}
	return filepath.Join(dir, "news", RecordKeyHex(rec)+".bin")
}

// ForgetSent removes the saved copy of a record that no node accepted.
func ForgetSent(dir string, rec *pb.Record) error {
	err := os.Remove(sentFile(dir, rec))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func saveNews(dir string, rec *pb.Record) error {
	if err := os.MkdirAll(filepath.Join(dir, "news"), 0o700); err != nil {
		return err
	}
	raw, err := proto.Marshal(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(sentFile(dir, rec), raw, 0o600)
}

// SignAnnouncement signs an ANNOUNCEMENT and keeps a copy in DIR/news/<record key>.bin.
func SignAnnouncement(dir string, a *pb.Announcement, now time.Time) (*pb.Record, error) {
	rec, err := signNews(dir, pb.RecordType_ANNOUNCEMENT, a, now)
	if err != nil {
		return nil, err
	}
	return rec, saveNews(dir, rec)
}

// Sent is a saved announcement.
type Sent struct {
	ID        string // hex(id), see NewsID
	Key       string // record key hex (author‖id)
	CreatedMs int64
	A         *pb.Announcement
	Deleted   bool // a deletion was signed (DIR/news/<id>.del)
}

func readRecord(path string) (*pb.Record, *pb.RecordBody, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var r pb.Record
	var b pb.RecordBody
	if proto.Unmarshal(raw, &r) != nil || proto.Unmarshal(r.Body, &b) != nil {
		return nil, nil, fmt.Errorf("%s: corrupt", path)
	}
	return &r, &b, nil
}

// ListAnnouncements returns saved announcements, oldest first.
func ListAnnouncements(dir string) ([]Sent, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "news", "*.bin"))
	var out []Sent
	for _, f := range files {
		_, b, err := readRecord(f)
		if err != nil {
			return nil, err
		}
		a := &pb.Announcement{}
		if proto.Unmarshal(b.Payload, a) != nil {
			return nil, fmt.Errorf("%s: corrupt", f)
		}
		key := strings.TrimSuffix(filepath.Base(f), ".bin")
		_, err = os.Stat(filepath.Join(dir, "news", key+".del"))
		out = append(out, Sent{ID: fmtHex(b.Id), Key: key, CreatedMs: b.CreatedMs, A: a, Deleted: err == nil})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedMs < out[j].CreatedMs })
	return out, nil
}

// SignAnnouncementDeleted signs a deletion of the saved announcement whose id starts with prefix (unique)
// and keeps it in DIR/news/<target key>.del.
func SignAnnouncementDeleted(dir, prefix string, now time.Time) (*pb.Record, error) {
	sent, err := ListAnnouncements(dir)
	if err != nil {
		return nil, err
	}
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	var match []string
	for _, s := range sent {
		if prefix != "" && strings.HasPrefix(s.ID, prefix) {
			match = append(match, s.Key)
		}
	}
	if len(match) != 1 {
		return nil, fmt.Errorf("id prefix %q matches %d announcements (see 'announce --list')", prefix, len(match))
	}
	target, _ := hex.DecodeString(match[0])
	rec, err := signNews(dir, pb.RecordType_ANNOUNCEMENT_DELETED, &pb.AnnouncementDeleted{Target: target}, now)
	if err != nil {
		return nil, err
	}
	return rec, saveNews(dir, rec)
}
