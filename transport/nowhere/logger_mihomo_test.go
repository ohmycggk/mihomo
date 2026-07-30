package nowhere

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
)

func TestLogInfoPreservesPercentInNowhereMessage(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	const message = "nowhere progress 100% complete"
	logInfo(message)

	select {
	case event := <-sub:
		if event.Payload != message {
			t.Fatalf("payload = %q, want %q", event.Payload, message)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for log event")
	}
}
