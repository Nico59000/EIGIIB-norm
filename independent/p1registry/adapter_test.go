package p1registry

import (
	"path/filepath"
	"testing"
)

func TestValidateFixture(t *testing.T) {
	root := filepath.Join("..", "..")
	result, err := ValidateFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.ManifestDigest != ManifestDigest {
		t.Fatalf("manifest digest = %s", result.ManifestDigest)
	}
	if len(result.Layers) != 3 {
		t.Fatalf("layers = %d", len(result.Layers))
	}
	if result.Boundary != Boundary {
		t.Fatalf("boundary = %s", result.Boundary)
	}
}
