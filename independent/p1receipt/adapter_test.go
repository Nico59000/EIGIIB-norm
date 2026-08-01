package p1receipt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type sourceIdentity struct {
	Algorithm string `json:"algorithm"`
	Bytes     int    `json:"bytes"`
	Digest    string `json:"digest"`
}

type sourceCapsule struct {
	Binding struct {
		TreeSize  int64 `json:"treeSize"`
		LeafIndex int64 `json:"leafIndex"`
	} `json:"binding"`
	SignedStatement struct {
		Data     string         `json:"data"`
		Identity sourceIdentity `json:"identity"`
	} `json:"signedStatement"`
	Receipt struct {
		Data     string         `json:"data"`
		Identity sourceIdentity `json:"identity"`
	} `json:"receipt"`
}

func positiveCarrier(t *testing.T) []byte {
	t.Helper()
	capsuleRaw, err := os.ReadFile("../../tests/fixtures/p1-a3/capsule.json")
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := os.ReadFile("../../tests/fixtures/p1-a3/ts-public-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	var source sourceCapsule
	if err := json.Unmarshal(capsuleRaw, &source); err != nil {
		t.Fatal(err)
	}
	c := map[string]any{
		"standard":        CarrierStandard,
		"profile":         Profile,
		"binding":         map[string]any{"treeSize": source.Binding.TreeSize, "leafIndex": source.Binding.LeafIndex, "signedStatementIdentity": source.SignedStatement.Identity},
		"signedStatement": map[string]any{"data": source.SignedStatement.Data, "identity": source.SignedStatement.Identity},
		"receipt":         map[string]any{"data": source.Receipt.Data, "identity": source.Receipt.Identity},
		"publicKeyPem":    string(keyRaw),
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPositive(t *testing.T) {
	result := Evaluate(positiveCarrier(t), "positive")
	if !result.Accepted || result.ErrorClass != nil || result.Boundary != "receipt-root" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestCoordinateMismatch(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(positiveCarrier(t), &document); err != nil {
		t.Fatal(err)
	}
	document["binding"].(map[string]any)["treeSize"] = float64(2)
	raw, _ := json.Marshal(document)
	result := Evaluate(raw, "coordinates")
	if result.ErrorClass == nil || *result.ErrorClass != "receipt.invalid-proof" || result.Boundary != "receipt-coordinates" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDetachedBinding(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(positiveCarrier(t), &document); err != nil {
		t.Fatal(err)
	}
	signed := document["signedStatement"].(map[string]any)
	decoded, _ := base64.StdEncoding.DecodeString(signed["data"].(string))
	decoded[len(decoded)-1] ^= 1
	signed["data"] = base64.StdEncoding.EncodeToString(decoded)
	sum := sha256.Sum256(decoded)
	signed["identity"] = map[string]any{"algorithm": "sha256", "bytes": len(decoded), "digest": hex.EncodeToString(sum[:])}
	raw, _ := json.Marshal(document)
	result := Evaluate(raw, "detached")
	if result.ErrorClass == nil || *result.ErrorClass != "receipt.invalid-proof" || result.Boundary != "receipt-detached-binding" {
		t.Fatalf("unexpected result: %#v", result)
	}
}
