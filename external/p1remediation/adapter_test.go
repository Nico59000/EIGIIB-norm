package p1remediation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixture(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	capsule := filepath.Join(root, "tests", "fixtures", "p1-a14", "capsule.json")
	if _, err := os.Stat(capsule); err != nil {
		t.Skip("repository fixture unavailable")
	}
	result, err := Evaluate(root, capsule)
	if err != nil {
		t.Fatal(err)
	}
	if result["overall_result"] != "conformant" {
		t.Fatalf("unexpected result: %v", result)
	}
}
