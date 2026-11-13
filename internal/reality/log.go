package reality

import (
	"log/slog"
	"strings"
	"sync/atomic"

	xlog "github.com/xtls/xray-core/common/log"
)

// Xray logs through one process-wide handler that defaults to stdout at debug level (access log included).
// We keep only its warnings and errors and send them to slog; connection outcomes go to the netlog instead.
var logger atomic.Pointer[slog.Logger]

// SetLogger directs Xray's warnings and errors to l (default: slog.Default()).
func SetLogger(l *slog.Logger) { logger.Store(l) }

type xrayLog struct{}

func (xrayLog) Handle(m xlog.Message) {
	g, ok := m.(*xlog.GeneralMessage)
	if !ok { // access log
		return
	}
	l := logger.Load()
	if l == nil {
		l = slog.Default()
	}
	switch g.Severity {
	case xlog.Severity_Error:
		l.Error("xray", "msg", g.String())
	case xlog.Severity_Warning:
		if s := g.String(); !strings.Contains(s, "core: Xray ") { // "Xray 26.x started", once per instance
			l.Warn("xray", "msg", s)
		}
	}
}

func init() { xlog.RegisterHandler(xrayLog{}) }
