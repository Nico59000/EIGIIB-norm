package p1time

import (
	"path/filepath"
	"testing"
)

func TestFixture(t *testing.T) {
	root := filepath.Clean("../..")
	result, err := Evaluate(root, filepath.Join(root, "tests/fixtures/p1-a11/capsule.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Boundary != "trusted-time-window-rollback-expiry-closure" || result.LastAcceptedTimestampUnix != 1785603600 {
		t.Fatalf("unexpected result: %+v", result)
	}
}
