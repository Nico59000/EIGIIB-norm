package p1authorization

import (
	"path/filepath"
	"testing"
)

func TestFixture(t *testing.T) {
	root := filepath.Clean("../..")
	result, err := Evaluate(root, filepath.Join(root, "tests/fixtures/p1-a10/capsule.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Boundary != "recovered-threshold-authorization" || result.Threshold != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
}
