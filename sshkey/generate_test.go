package sshkey

import "testing"

func TestGeneratePairUnsupportedType(t *testing.T) {
	if _, _, err := GeneratePair("bad", 0, ""); err == nil {
		t.Fatalf("expected unsupported key type error")
	}
}
