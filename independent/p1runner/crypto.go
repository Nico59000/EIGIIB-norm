package p1runner

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

func canonical(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func canonicalRaw(raw json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return canonical(value)
}

func shaCanonical(v any) (string, error) {
	data, err := canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func shaRaw(raw json.RawMessage) (string, error) {
	data, err := canonicalRaw(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func verifyEnvelope(env Envelope, expectedKeyID, publicKeyPath string) error {
	if env.KeyID != expectedKeyID {
		return errors.New("signing key mismatch")
	}
	digest, err := shaRaw(env.Payload)
	if err != nil {
		return err
	}
	if digest != env.PayloadSHA256 {
		return errors.New("signed payload digest mismatch")
	}
	pemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("invalid public key pem")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("public key is not Ed25519")
	}
	signature, err := base64.StdEncoding.DecodeString(env.SignatureBase64)
	if err != nil {
		return err
	}
	payload, err := canonicalRaw(env.Payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

func validHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
