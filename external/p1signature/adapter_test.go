package p1signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func testCarrier(t *testing.T) map[string]any {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hello":"world"}`)
	signature := ed25519.Sign(privateKey, pae(PayloadType, payload))
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "p1-a2-ed25519-spki-sha256:" + identity(der)["digest"].(string)
	return map[string]any{
		"standard": CarrierStandard,
		"profile":  Profile,
		"manifest": map[string]any{
			"members": []any{
				map[string]any{"name": "payload", "identity": identity(payload)},
				map[string]any{"name": "signature", "identity": identity(signature)},
				map[string]any{"name": "public-key-spki", "identity": identity(der)},
			},
		},
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(payload),
			"payloadType": PayloadType,
			"signatures": []any{
				map[string]any{
					"keyid": keyID,
					"sig":   base64.StdEncoding.EncodeToString(signature),
				},
			},
		},
		"publicKeyPem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
}

func encoded(t *testing.T, carrier map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(carrier)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signatureRow(carrier map[string]any) map[string]any {
	envelope := carrier["dsseEnvelope"].(map[string]any)
	signatures := envelope["signatures"].([]any)
	return signatures[0].(map[string]any)
}

func members(carrier map[string]any) []any {
	return carrier["manifest"].(map[string]any)["members"].([]any)
}

func TestPositiveCarrier(t *testing.T) {
	result := Evaluate(encoded(t, testCarrier(t)), "positive")
	if !result.Accepted || result.ErrorClass != nil || result.Boundary != "signature" {
		t.Fatalf("unexpected positive result: %+v", result)
	}
}

func TestManifestOrderPrecedesSignatureFailure(t *testing.T) {
	carrier := testCarrier(t)
	rows := members(carrier)
	rows[0], rows[1] = rows[1], rows[0]
	row := signatureRow(carrier)
	signature, _ := base64.StdEncoding.DecodeString(row["sig"].(string))
	signature[0] ^= 1
	row["sig"] = base64.StdEncoding.EncodeToString(signature)
	rows[1].(map[string]any)["identity"] = identity(signature)
	result := Evaluate(encoded(t, carrier), "multi")
	if result.Accepted || result.ErrorClass == nil ||
		*result.ErrorClass != "manifest.invalid" || result.Boundary != "manifest" {
		t.Fatalf("unexpected precedence result: %+v", result)
	}
}

func TestWrongPayloadTypeIsMalformed(t *testing.T) {
	carrier := testCarrier(t)
	carrier["dsseEnvelope"].(map[string]any)["payloadType"] = "application/octet-stream"
	result := Evaluate(encoded(t, carrier), "payload-type")
	if result.ErrorClass == nil || *result.ErrorClass != "signature.malformed" ||
		result.Boundary != "dsse" {
		t.Fatalf("unexpected payload type result: %+v", result)
	}
}

func TestBitflipIsInvalidSignature(t *testing.T) {
	carrier := testCarrier(t)
	row := signatureRow(carrier)
	signature, _ := base64.StdEncoding.DecodeString(row["sig"].(string))
	signature[0] ^= 1
	row["sig"] = base64.StdEncoding.EncodeToString(signature)
	members(carrier)[1].(map[string]any)["identity"] = identity(signature)
	result := Evaluate(encoded(t, carrier), "bitflip")
	if result.ErrorClass == nil || *result.ErrorClass != "signature.invalid" ||
		result.Boundary != "signature" {
		t.Fatalf("unexpected bitflip result: %+v", result)
	}
}

func TestTruncatedSignatureIsMalformed(t *testing.T) {
	carrier := testCarrier(t)
	row := signatureRow(carrier)
	signature, _ := base64.StdEncoding.DecodeString(row["sig"].(string))
	signature = signature[:len(signature)-1]
	row["sig"] = base64.StdEncoding.EncodeToString(signature)
	members(carrier)[1].(map[string]any)["identity"] = identity(signature)
	result := Evaluate(encoded(t, carrier), "truncated")
	if result.ErrorClass == nil || *result.ErrorClass != "signature.malformed" ||
		result.Boundary != "signature-carrier" {
		t.Fatalf("unexpected truncated result: %+v", result)
	}
}
