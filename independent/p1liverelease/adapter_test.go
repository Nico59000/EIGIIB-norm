package p1liverelease

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestValidate(t *testing.T) {
	portable, err := Validate(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if portable.ReleaseTag != ReleaseTag || portable.PeeledCommitSHA != SourceA14Commit {
		t.Fatal("portable identity mismatch")
	}
}

func TestRejectMutatedEvidence(t *testing.T) {
	root := repositoryRoot(t)
	temp := t.TempDir()
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(temp, rel)
		if info.IsDir() {
			return os.MkdirAll(dest, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, info.Mode())
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(temp, "tests", "fixtures", "p1-a15", "live-release-evidence.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if data[i] == 'v' {
			data[i] = 'x'
			break
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(temp); err == nil {
		t.Fatal("mutated evidence was accepted")
	}
}
