package nowhere

import "github.com/metacubex/mihomo/transport/nowhere/core/diagnostic"

func formatDiagnosticEvent(event diagnostic.Event) string {
	return diagnostic.FormatEvent(event)
}
