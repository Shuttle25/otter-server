package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ottermsg/server/internal/records"
)

// sigFile holds the v1 signature cut-over (D110), in ms since the epoch; absent = not set.
const sigFile = "sig_v1_until_ms"

// SigV1Until is the cut-over time stored in DIR (0 = not set).
func SigV1Until(dir string) int64 {
	b, err := os.ReadFile(filepath.Join(dir, sigFile))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// SetSigV1Until sets the v1 signature cut-over once (D110); it can never be lowered, raised or cleared.
func SetSigV1Until(dir string, ms int64) error {
	cur := SigV1Until(dir)
	switch {
	case ms <= 0:
		return errors.New("--sig-v1-until must be a time")
	case cur == ms:
		return nil
	case cur != 0:
		return fmt.Errorf("the cut-over is already set to %d ms and cannot change", cur)
	}
	return os.WriteFile(filepath.Join(dir, sigFile), []byte(fmt.Sprintf("%d\n", ms)), 0o644)
}

// adminSig: manifests, network records, bootstrap invites and announcements are signed v2 once the cut-over is set
// (D109).
func adminSig(st *State, dir string) records.SigContext {
	sc := records.ContextFor(st.NetworkPub, nil)
	sc.V2 = SigV1Until(dir) != 0
	return sc
}
