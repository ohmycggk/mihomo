package inbound

import "testing"

func TestNowhereNextMorphInherit(t *testing.T) {
	next := &NowhereNextOption{Server: "origin.example", Port: 2080, Password: "k"}
	cfg := nowhereNextConfig(next, true)
	if cfg == nil || !cfg.Morph {
		t.Fatal("omitted next.morph should inherit listener morph")
	}
	off := false
	next.Morph = &off
	cfg = nowhereNextConfig(next, true)
	if cfg.Morph {
		t.Fatal("explicit next.morph=false should override inherited morph")
	}
	on := true
	next.Morph = &on
	cfg = nowhereNextConfig(next, false)
	if !cfg.Morph {
		t.Fatal("explicit next.morph=true should override listener morph=0")
	}
}
