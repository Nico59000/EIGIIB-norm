package bridge

import (
	"os"
	"path/filepath"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func copyFile(t *testing.T, source, target string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixtureCopy(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	target := t.TempDir()
	paths := []string{
		"tests/fixtures/p1-a1/aggregate.json",
		"tests/fixtures/p1-a1/capsule.json",
		"tests/fixtures/p1-a2/bundle.json",
		"tests/fixtures/p1-a2/public-key.pem",
		"tests/fixtures/p1-a3/capsule.json",
		"tests/fixtures/p1-a3/issuer-public-key.pem",
		"tests/fixtures/p1-a3/ts-public-key.pem",
		"tests/fixtures/p1-a4/chain.json",
	}
	for _, path := range paths {
		copyFile(t, filepath.Join(source, path), filepath.Join(target, path))
	}
	return target
}

func TestCanonicalExternalObservation(t *testing.T) {
	if err := Observe(repositoryRoot(t)); err != nil {
		t.Fatalf("external observation failed: %v", err)
	}
}

func TestCanonicalBridgeProjection(t *testing.T) {
	result := Verify(repositoryRoot(t))
	if result.StructuralResult != "conformant" || result.ExternalObservationResult != "conformant" || result.ExternalLibraryResult != "valid" || result.EndToEndResult != "conformant" {
		t.Fatalf("unexpected bridge result: %+v", result)
	}
}

func TestWrongIssuerKeyRejected(t *testing.T) {
	root := fixtureCopy(t)
	copyFile(t,
		filepath.Join(root, "tests/fixtures/p1-a2/public-key.pem"),
		filepath.Join(root, "tests/fixtures/p1-a3/issuer-public-key.pem"),
	)
	if err := Observe(root); err == nil {
		t.Fatal("external observation accepted the wrong issuer key")
	}
}

func TestTruncatedReceiptRejected(t *testing.T) {
	root := fixtureCopy(t)
	path := filepath.Join(root, "tests/fixtures/p1-a3/capsule.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := len(raw) - 1; index >= 0; index-- {
		if raw[index] == 'A' {
			raw[index] = 'B'
			break
		}
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Observe(root); err == nil {
		t.Fatal("external observation accepted a modified capsule")
	}
}

func TestDuplicateJSONRejected(t *testing.T) {
	if _, err := strictJSON([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate JSON member accepted")
	}
}
