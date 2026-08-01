package p1receipt

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
	"io"
)

func readCarrier(raw []byte) (carrier, []byte, []byte, ed25519.PublicKey, []byte, error) {
	var c carrier
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, nil, nil, nil, nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return c, nil, nil, nil, nil, errors.New("trailing JSON")
	}
	if c.Standard != CarrierStandard || c.Profile != Profile {
		return c, nil, nil, nil, nil, errors.New("carrier constants")
	}
	if c.Binding.SignedStatementIdentity.Algorithm != "sha256" || c.Binding.SignedStatementIdentity.Bytes != expectedStatementBytes || c.Binding.SignedStatementIdentity.Digest != expectedStatementDigest {
		return c, nil, nil, nil, nil, errors.New("binding identity")
	}
	signedRaw, err := canonicalBase64(c.SignedStatement.Data)
	if err != nil {
		return c, nil, nil, nil, nil, err
	}
	receiptRaw, err := canonicalBase64(c.Receipt.Data)
	if err != nil {
		return c, nil, nil, nil, nil, err
	}
	if !sameIdentity(c.SignedStatement.Identity, signedRaw) || !sameIdentity(c.Receipt.Identity, receiptRaw) {
		return c, nil, nil, nil, nil, errors.New("carrier identity")
	}
	publicKey, der, err := readEd25519([]byte(c.PublicKeyPEM))
	if err != nil {
		return c, nil, nil, nil, nil, err
	}
	return c, signedRaw, receiptRaw, publicKey, der, nil
}

func canonicalBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("base64 carrier")
	}
	return raw, nil
}
func sameIdentity(c identityCarrier, raw []byte) bool {
	sum := sha256.Sum256(raw)
	return c.Algorithm == "sha256" && c.Bytes == len(raw) && c.Digest == hex.EncodeToString(sum[:])
}
func readEd25519(raw []byte) (ed25519.PublicKey, []byte, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("invalid key")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize || len(block.Bytes) != 44 {
		return nil, nil, errors.New("not Ed25519")
	}
	return key, block.Bytes, nil
}
