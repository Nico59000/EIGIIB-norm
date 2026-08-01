package p1receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const CarrierStandard = "EIGIIB-P1-A7.6-CARRIER-1.0"
const Profile = "receipt-detached-proof-root-negative-replay-v1"
const expectedStatementDigest = "27c960d31e9afbf454c8bb6dbdd396309b3dec629f58d8f5c87553864e579d81"
const expectedStatementBytes = 396

type carrier struct {
	SignedRaw  []byte
	ReceiptRaw []byte
	PublicKey  ed25519.PublicKey
	PublicDER  []byte
	TreeSize   int64
	LeafIndex  int64
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
		return nil, errors.New("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("JSON root is not object")
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

func asObject(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}
func asText(value any) (string, bool) { result, ok := value.(string); return result, ok }
func asInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	return parsed, err == nil
}

func canonicalBase64(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return nil, errors.New("base64 carrier invalid")
	}
	return DecodeBase64(text)
}

func sameIdentity(value any, raw []byte) bool {
	row, ok := asObject(value)
	if !ok || !exactKeys(row, "algorithm", "bytes", "digest") {
		return false
	}
	algorithm, aok := asText(row["algorithm"])
	digest, dok := asText(row["digest"])
	length, lok := asInteger(row["bytes"])
	sum := sha256.Sum256(raw)
	return aok && dok && lok && algorithm == "sha256" && digest == hex.EncodeToString(sum[:]) && length == int64(len(raw))
}

func expectedStatementIdentity(value any) bool {
	row, ok := asObject(value)
	if !ok || !exactKeys(row, "algorithm", "bytes", "digest") {
		return false
	}
	algorithm, aok := asText(row["algorithm"])
	digest, dok := asText(row["digest"])
	length, lok := asInteger(row["bytes"])
	return aok && dok && lok && algorithm == "sha256" && digest == expectedStatementDigest && length == expectedStatementBytes
}

func readEd25519(raw []byte) (ed25519.PublicKey, []byte, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("invalid public key PEM")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize || len(block.Bytes) != 44 {
		return nil, nil, errors.New("key is not Ed25519 SPKI")
	}
	return key, block.Bytes, nil
}

func readCarrier(raw []byte) (carrier, error) {
	root, err := strictJSON(raw)
	if err != nil {
		return carrier{}, err
	}
	if !exactKeys(root, "standard", "profile", "binding", "signedStatement", "receipt", "publicKeyPem") {
		return carrier{}, errors.New("carrier fields differ")
	}
	standard, _ := asText(root["standard"])
	profile, _ := asText(root["profile"])
	if standard != CarrierStandard || profile != Profile {
		return carrier{}, errors.New("carrier constants differ")
	}
	binding, bok := asObject(root["binding"])
	signed, sok := asObject(root["signedStatement"])
	receipt, rok := asObject(root["receipt"])
	if !bok || !sok || !rok || !exactKeys(binding, "treeSize", "leafIndex", "signedStatementIdentity") || !exactKeys(signed, "data", "identity") || !exactKeys(receipt, "data", "identity") {
		return carrier{}, errors.New("carrier nested fields differ")
	}
	treeSize, tok := asInteger(binding["treeSize"])
	leafIndex, lok := asInteger(binding["leafIndex"])
	if !tok || !lok || !expectedStatementIdentity(binding["signedStatementIdentity"]) {
		return carrier{}, errors.New("binding carrier invalid")
	}
	signedRaw, err := canonicalBase64(signed["data"])
	if err != nil {
		return carrier{}, err
	}
	receiptRaw, err := canonicalBase64(receipt["data"])
	if err != nil {
		return carrier{}, err
	}
	if !sameIdentity(signed["identity"], signedRaw) || !sameIdentity(receipt["identity"], receiptRaw) {
		return carrier{}, errors.New("carrier identity mismatch")
	}
	keyText, ok := asText(root["publicKeyPem"])
	if !ok {
		return carrier{}, errors.New("public key carrier invalid")
	}
	key, der, err := readEd25519([]byte(keyText))
	if err != nil {
		return carrier{}, err
	}
	return carrier{SignedRaw: signedRaw, ReceiptRaw: receiptRaw, PublicKey: key, PublicDER: der, TreeSize: treeSize, LeafIndex: leafIndex}, nil
}
