package nowhere

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/log"
)

func formatArgs(args ...any) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, fmt.Sprint(a))
	}
	return strings.Join(parts, " ")
}

func logDebug(args ...any) {
	msg := formatArgs(args...)
	if strings.HasPrefix(msg, "nowhere ") {
		log.Debugln("%s", msg)
		return
	}
	log.Debugln("[Nowhere] %s", msg)
}

func logInfo(args ...any) {
	msg := formatArgs(args...)
	if strings.HasPrefix(msg, "nowhere ") {
		log.Infoln("%s", msg)
		return
	}
	log.Infoln("[Nowhere] %s", msg)
}

func logWarn(args ...any) {
	msg := formatArgs(args...)
	if strings.HasPrefix(msg, "nowhere ") {
		log.Warnln("%s", msg)
		return
	}
	log.Warnln("[Nowhere] %s", msg)
}

func logError(args ...any) {
	msg := formatArgs(args...)
	if strings.HasPrefix(msg, "nowhere ") {
		log.Errorln("%s", msg)
		return
	}
	log.Errorln("[Nowhere] %s", msg)
}
