package p1runner

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestExactReport(t *testing.T) {
	root := repoRoot(t)
	actual, err := LoadAndReport(root)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(filepath.Join(root, "tests", "fixtures", "p1-a20", "expected-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("report differs\nactual: %s\nexpected: %s", actual, expected)
	}
}

func copyFixture(t *testing.T, root, temp string) string {
	t.Helper()
	source := filepath.Join(root, "tests", "fixtures", "p1-a20")
	destination := filepath.Join(temp, "tests", "fixtures", "p1-a20")
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	return destination
}

func TestRejectTamperedRunnerIdentity(t *testing.T) {
	root := repoRoot(t)
	fixture := copyFixture(t, root, t.TempDir())
	routePath := filepath.Join(fixture, "route-01.json")
	data, err := os.ReadFile(routePath)
	if err != nil {
		t.Fatal(err)
	}
	var route map[string]any
	if err := json.Unmarshal(data, &route); err != nil {
		t.Fatal(err)
	}
	route["runnerIdentitySha256"] = string(bytes.Repeat([]byte{'0'}, 64))
	mutated, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(routePath, append(mutated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAndReport(filepath.Clean(filepath.Join(fixture, "..", "..", ".."))); err == nil {
		t.Fatal("tampered runner identity was accepted")
	}
}
