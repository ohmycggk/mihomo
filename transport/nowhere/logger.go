package nowhere

import (
	"context"

	"github.com/metacubex/mihomo/transport/nowhere/core/diagnostic"
)

type MihomoObserver struct{}

func (MihomoObserver) Observe(_ context.Context, event diagnostic.Event) {
	msg := formatDiagnosticEvent(event)
	switch event.Level {
	case diagnostic.LevelDebug:
		logDebug(msg)
	case diagnostic.LevelWarn:
		logWarn(msg)
	case diagnostic.LevelError:
		logError(msg)
	default:
		logInfo(msg)
	}
}

var _ diagnostic.Observer = MihomoObserver{}
