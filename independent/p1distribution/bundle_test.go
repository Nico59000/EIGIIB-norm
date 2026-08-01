package p1distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestGitBlobSHA1(t *testing.T) {
	if got := GitBlobSHA1([]byte("test\n")); got != "9daeafb9864cf43055ae93beb0afd6c7d144bfa4" {
		t.Fatalf("unexpected Git blob identity: %s", got)
	}
}

func TestClosedUSTARIsDeterministic(t *testing.T) {
	entries := []archiveEntry{{Path: "release/source/a.txt", Mode: 0644, Data: []byte("abc")}}
	first, err := buildUSTAR(entries)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildUSTAR(entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("USTAR bytes differ")
	}
	sum := sha256.Sum256(first)
	if hex.EncodeToString(sum[:]) == "" || len(first)%512 != 0 {
		t.Fatal("invalid deterministic USTAR")
	}
}
