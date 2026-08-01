package p1signature

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const Standard = "EIGIIB-P1-A7.4-1.0"
const CarrierStandard = "EIGIIB-P1-A7.4-CARRIER-1.0"
const Profile = "manifest-dsse-signature-carrier-v1"
const PayloadType = "application/vnd.in-toto+json"
const Route = "external-go-cose"

var memberOrder = []string{"payload", "signature", "public-key-spki"}

type Result struct {
	Standard   string  `json:"standard"`
	Route      string  `json:"route"`
	VectorID   string  `json:"vector_id"`
	Accepted   bool    `json:"accepted"`
	ErrorClass *string `json:"error_class"`
	Boundary   string  `json:"boundary"`
}

type portableReject struct {
	class    string
	boundary string
}

func (p portableReject) Error() string { return p.class }

func reject(class, boundary string) error {
	return portableReject{class: class, boundary: boundary}
}

func parseValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object key is not string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON member: %s", key)
			}
			value, err := parseValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object terminator")
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			value, err := parseValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array terminator")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func strictJSON(raw []byte) (map[string]any, error) {
	if !json.Valid(raw) {
		return nil, reject("signature.malformed", "signature-carrier")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, reject("signature.malformed", "signature-carrier")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, reject("signature.malformed", "signature-carrier")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, reject("manifest.invalid", "manifest")
	}
	return object, nil
}

func exactKeys(object map[string]any, names ...string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}

func object(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func array(value any) ([]any, bool) {
	result, ok := value.([]any)
	return result, ok
}

func text(value any) (string, bool) {
	result, ok := value.(string)
	return result, ok
}

func integer(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(number.String())
	return parsed, err == nil
}

func canonicalBase64(value any) ([]byte, error) {
	input, ok := value.(string)
	if !ok || input == "" {
		return nil, reject("signature.malformed", "signature-carrier")
	}
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != input {
		return nil, reject("signature.malformed", "signature-carrier")
	}
	return decoded, nil
}

func identity(raw []byte) map[string]any {
	sum := sha256.Sum256(raw)
	return map[string]any{
		"algorithm": "sha256",
		"digest":    hex.EncodeToString(sum[:]),
		"bytes":     json.Number(strconv.Itoa(len(raw))),
	}
}

func sameIdentity(value any, raw []byte) bool {
	row, ok := object(value)
	if !ok || !exactKeys(row, "algorithm", "digest", "bytes") {
		return false
	}
	algorithm, aok := text(row["algorithm"])
	digest, dok := text(row["digest"])
	length, lok := integer(row["bytes"])
	expected := sha256.Sum256(raw)
	return aok && dok && lok &&
		algorithm == "sha256" &&
		digest == hex.EncodeToString(expected[:]) &&
		length == len(raw)
}

func parsePublicKey(value any) (ed25519.PublicKey, []byte, error) {
	input, ok := value.(string)
	if !ok {
		return nil, nil, reject("signature.malformed", "signature-carrier")
	}
	block, rest := pem.Decode([]byte(input))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, reject("signature.malformed", "signature-carrier")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, reject("signature.malformed", "signature-carrier")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || len(block.Bytes) != 44 {
		return nil, nil, reject("signature.malformed", "signature-carrier")
	}
	return publicKey, block.Bytes, nil
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(
		"DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType +
			" " + strconv.Itoa(len(payload)) + " " + string(payload),
	)
}

func carrierParts(root map[string]any) (ed25519.PublicKey, string, []byte, []byte, error) {
	if !exactKeys(root, "standard", "profile", "manifest", "dsseEnvelope", "publicKeyPem") {
		return nil, "", nil, nil, reject("manifest.invalid", "manifest")
	}
	standard, _ := text(root["standard"])
	profile, _ := text(root["profile"])
	if standard != CarrierStandard || profile != Profile {
		return nil, "", nil, nil, reject("manifest.invalid", "manifest")
	}
	manifest, ok := object(root["manifest"])
	if !ok || !exactKeys(manifest, "members") {
		return nil, "", nil, nil, reject("manifest.invalid", "manifest")
	}
	members, ok := array(manifest["members"])
	if !ok || len(members) != len(memberOrder) {
		return nil, "", nil, nil, reject("manifest.invalid", "manifest")
	}
	for index, expectedName := range memberOrder {
		row, ok := object(members[index])
		if !ok || !exactKeys(row, "name", "identity") {
			return nil, "", nil, nil, reject("manifest.invalid", "manifest")
		}
		name, _ := text(row["name"])
		if name != expectedName {
			return nil, "", nil, nil, reject("manifest.invalid", "manifest")
		}
	}

	envelope, ok := object(root["dsseEnvelope"])
	if !ok || !exactKeys(envelope, "payload", "payloadType", "signatures") {
		return nil, "", nil, nil, reject("signature.malformed", "signature-carrier")
	}
	payload, err := canonicalBase64(envelope["payload"])
	if err != nil {
		return nil, "", nil, nil, err
	}
	signatures, ok := array(envelope["signatures"])
	if !ok || len(signatures) != 1 {
		return nil, "", nil, nil, reject("signature.malformed", "signature-carrier")
	}
	signatureRow, ok := object(signatures[0])
	if !ok || !exactKeys(signatureRow, "keyid", "sig") {
		return nil, "", nil, nil, reject("signature.malformed", "signature-carrier")
	}
	signature, err := canonicalBase64(signatureRow["sig"])
	if err != nil {
		return nil, "", nil, nil, err
	}
	keyID, ok := text(signatureRow["keyid"])
	if !ok || keyID == "" {
		return nil, "", nil, nil, reject("signature.malformed", "signature-carrier")
	}
	publicKey, der, err := parsePublicKey(root["publicKeyPem"])
	if err != nil {
		return nil, "", nil, nil, err
	}

	memberRows := make([]map[string]any, len(members))
	for index, value := range members {
		memberRows[index], _ = object(value)
	}
	if !sameIdentity(memberRows[0]["identity"], payload) ||
		!sameIdentity(memberRows[1]["identity"], signature) ||
		!sameIdentity(memberRows[2]["identity"], der) {
		return nil, "", nil, nil, reject("manifest.invalid", "manifest")
	}

	payloadType, ok := text(envelope["payloadType"])
	if !ok || payloadType != PayloadType {
		return nil, "", nil, nil, reject("signature.malformed", "dsse")
	}
	sum := sha256.Sum256(der)
	expectedKeyID := "p1-a2-ed25519-spki-sha256:" + hex.EncodeToString(sum[:])
	if keyID != expectedKeyID || len(signature) != ed25519.SignatureSize {
		return nil, "", nil, nil, reject("signature.malformed", "signature-carrier")
	}
	return publicKey, payloadType, payload, signature, nil
}

func Evaluate(raw []byte, vectorID string) Result {
	root, err := strictJSON(raw)
	if err == nil {
		var publicKey ed25519.PublicKey
		var payloadType string
		var payload, signature []byte
		publicKey, payloadType, payload, signature, err = carrierParts(root)
		if err == nil && !ed25519.Verify(publicKey, pae(payloadType, payload), signature) {
			err = reject("signature.invalid", "signature")
		}
	}
	if err != nil {
		var rejected portableReject
		if errors.As(err, &rejected) {
			class := rejected.class
			return Result{
				Standard: Standard, Route: Route, VectorID: vectorID,
				Accepted: false, ErrorClass: &class, Boundary: rejected.boundary,
			}
		}
		class := "internal.unmapped"
		return Result{
			Standard: Standard, Route: Route, VectorID: vectorID,
			Accepted: false, ErrorClass: &class, Boundary: "signature-carrier",
		}
	}
	return Result{
		Standard: Standard, Route: Route, VectorID: vectorID,
		Accepted: true, ErrorClass: nil, Boundary: "signature",
	}
}
