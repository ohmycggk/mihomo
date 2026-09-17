package nowhere

import "testing"

func TestMorphSharedKey(t *testing.T) {
	if got := MorphSharedKey(false, "secret"); got != nil {
		t.Fatalf("disabled MorphSharedKey = %q, want nil", got)
	}
	if got := MorphSharedKey(true, ""); got != nil {
		t.Fatalf("empty-password MorphSharedKey = %q, want nil", got)
	}
	if got := string(MorphSharedKey(true, "secret")); got != "secret" {
		t.Fatalf("MorphSharedKey = %q, want secret", got)
	}
}
