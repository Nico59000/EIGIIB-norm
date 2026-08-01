package p1transparency

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
	"os"
	"path/filepath"
	"strings"
)

func parseValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		out := map[string]any{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kt.(string)
			if !ok {
				return nil, errors.New("json key")
			}
			if _, exists := out[key]; exists {
				return nil, errors.New("duplicate JSON member")
			}
			value, err := parseValue(d)
			if err != nil {
				return nil, err
			}
			out[key] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("json object")
		}
		return out, nil
	case '[':
		out := []any{}
		for d.More() {
			value, err := parseValue(d)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("json array")
		}
		return out, nil
	}
	return nil, errors.New("json delimiter")
}

func strictJSON(raw []byte) (any, error) {
	if !json.Valid(raw) {
		return nil, errors.New("invalid json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := parseValue(d)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing json")
	}
	return value, nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func decodeStruct(raw []byte, out any) error {
	value, err := strictJSON(raw)
	if err != nil {
		return err
	}
	canonical, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("noncanonical json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(out); err != nil {
		return err
	}
	return nil
}

func identity(raw []byte) Identity {
	sum := sha256.Sum256(raw)
	return Identity{Algorithm: "sha256", Bytes: len(raw), Digest: hex.EncodeToString(sum[:])}
}
func sameIdentity(got Identity, raw []byte) bool { return got == identity(raw) }

func decodeB64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("base64")
	}
	return raw, nil
}

func carrierBytes(carrier DataCarrier) ([]byte, error) {
	raw, err := decodeB64(carrier.Data)
	if err != nil || !sameIdentity(carrier.Identity, raw) {
		return nil, errors.New("carrier identity")
	}
	return raw, nil
}

func safeRead(root, rel string) ([]byte, string, error) {
	if rel == "" || strings.Contains(rel, "\\") || strings.HasPrefix(rel, "/") {
		return nil, "", errors.New("unsafe path")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, "", errors.New("unsafe path")
		}
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return nil, "", err
	}
	path, err := filepath.Abs(filepath.Join(root, rel))
	if err != nil {
		return nil, "", err
	}
	if path != base && !strings.HasPrefix(path, base+string(os.PathSeparator)) {
		return nil, "", errors.New("path escape")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("unsafe file")
	}
	raw, err := os.ReadFile(path)
	return raw, path, err
}

func readKey(root string, carrier KeyCarrier, requireID bool) (ed25519.PublicKey, []byte, string, error) {
	if requireID && carrier.ID == "" {
		return nil, nil, "", errors.New("delegate id")
	}
	raw, path, err := safeRead(root, carrier.Path)
	if err != nil {
		return nil, nil, "", err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, "", errors.New("pem")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, "", err
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize || len(block.Bytes) != 44 || !sameIdentity(carrier.SPKI, block.Bytes) {
		return nil, nil, "", errors.New("spki")
	}
	return key, block.Bytes, path, nil
}

func expectCanonical(raw []byte, expected any, label string) error {
	want, err := canonicalJSON(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, want) {
		return fmt.Errorf("%s semantics", label)
	}
	return nil
}
