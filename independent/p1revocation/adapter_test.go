package p1revocation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixture(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	capsule := filepath.Join(root, "tests", "fixtures", "p1-a13", "capsule.json")
	if _, err := os.Stat(capsule); err != nil {
		t.Skip("repository fixture unavailable")
	}
	r, err := Evaluate(root, capsule)
	if err != nil {
		t.Fatal(err)
	}
	if r["overall_result"] != "conformant" {
		t.Fatalf("unexpected result: %v", r)
	}
}
