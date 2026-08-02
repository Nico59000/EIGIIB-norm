package p1interoperability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func TestRun(t *testing.T) {
	r, err := Run(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if r["overallResult"] != "conformant" || r["routeCount"] != 6 {
		t.Fatalf("unexpected report: %#v", r)
	}
}

func TestExactExpectedReport(t *testing.T) {
	r, err := Run(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(filepath.Join(repoRoot(t), "tests", "fixtures", "p1-a19", "expected-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expected, &b); err != nil {
		t.Fatal(err)
	}
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(aa) != string(bb) {
		t.Fatalf("report mismatch\n%s\n%s", aa, bb)
	}
}
