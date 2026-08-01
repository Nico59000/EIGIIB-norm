package p1structural

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(dir, "..", ".."))
}

func loadSeed(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "tests", "fixtures", "p1-a7", "source", "a7.3-seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateJSON(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPositiveSeed(t *testing.T) {
	result := Evaluate(loadSeed(t), "positive")
	if !result.Accepted || result.ErrorClass != nil || result.Boundary != "projection" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestIdentityLengthPrecedesDigest(t *testing.T) {
	raw := mutateJSON(t, loadSeed(t), func(value map[string]any) {
		payload := value["payload"].(map[string]any)
		identity := payload["identity"].(map[string]any)
		identity["bytes"] = float64(5)
		identity["digest"] = "0000000000000000000000000000000000000000000000000000000000000000"
	})
	result := Evaluate(raw, "multi-identity")
	if result.ErrorClass == nil || *result.ErrorClass != "identity.length-mismatch" || result.Boundary != "identity.length" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestProjectionMissingField(t *testing.T) {
	raw := mutateJSON(t, loadSeed(t), func(value map[string]any) {
		projection := value["projection"].(map[string]any)
		delete(projection, "end_to_end_result")
	})
	result := Evaluate(raw, "projection")
	if result.ErrorClass == nil || *result.ErrorClass != "projection.invalid" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBase64PrecedesOtherStructuralDefects(t *testing.T) {
	raw := mutateJSON(t, loadSeed(t), func(value map[string]any) {
		payload := value["payload"].(map[string]any)
		payload["base64"] = payload["base64"].(string) + "="
		payload["path"] = "../escape.json"
		identity := payload["identity"].(map[string]any)
		identity["bytes"] = float64(5)
		projection := value["projection"].(map[string]any)
		delete(projection, "end_to_end_result")
	})
	result := Evaluate(raw, "multi")
	if result.ErrorClass == nil || *result.ErrorClass != "encoding.noncanonical-base64" || result.Boundary != "base64" {
		t.Fatalf("unexpected result: %#v", result)
	}
}
