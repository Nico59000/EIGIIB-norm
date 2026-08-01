package p1remediation

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

func decodeCanonical(raw []byte) (any, error) {
	v, err := strictJSON(raw)
	if err != nil {
		return nil, err
	}
	enc, err := canonicalJSON(v)
	if err != nil || !bytes.Equal(enc, raw) {
		return nil, errors.New("noncanonical json")
	}
	return v, nil
}

func identity(raw []byte) map[string]any {
	s := sha256.Sum256(raw)
	return map[string]any{"algorithm": "sha256", "bytes": len(raw), "digest": hex.EncodeToString(s[:])}
}
func sameJSON(a, b any) bool {
	ar, _ := json.Marshal(a)
	br, _ := json.Marshal(b)
	return bytes.Equal(ar, br)
}
func obj(v any) (map[string]any, bool) { x, ok := v.(map[string]any); return x, ok }
func arr(v any) ([]any, bool)          { x, ok := v.([]any); return x, ok }
func str(v any) (string, bool)         { x, ok := v.(string); return x, ok }
func integer(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, e := x.Int64()
		return n, e == nil
	case int:
		return int64(x), true
	case int64:
		return x, true
	case float64:
		return int64(x), x == float64(int64(x))
	}
	return 0, false
}
func requireKeys(m map[string]any, names ...string) bool {
	if len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}
func decodeB64(s string) ([]byte, error) {
	raw, e := base64.StdEncoding.DecodeString(s)
	if e != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, errors.New("base64")
	}
	return raw, nil
}
func carrierBytes(v any) ([]byte, error) {
	m, ok := obj(v)
	if !ok || !requireKeys(m, "data", "identity") {
		return nil, errors.New("carrier")
	}
	s, ok := str(m["data"])
	if !ok {
		return nil, errors.New("carrier data")
	}
	raw, e := decodeB64(s)
	if e != nil || !sameJSON(m["identity"], identity(raw)) {
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
	base, e := filepath.Abs(root)
	if e != nil {
		return nil, "", e
	}
	path, e := filepath.Abs(filepath.Join(root, rel))
	if e != nil {
		return nil, "", e
	}
	if path != base && !strings.HasPrefix(path, base+string(os.PathSeparator)) {
		return nil, "", errors.New("path escape")
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("unsafe file")
	}
	raw, e := os.ReadFile(path)
	return raw, path, e
}
func readKey(root string, carrier map[string]any, required []string) (ed25519.PublicKey, []byte, error) {
	pathValue, ok := str(carrier["path"])
	if !ok {
		return nil, nil, errors.New("key path")
	}
	for _, k := range required {
		if _, ok := carrier[k]; !ok {
			return nil, nil, errors.New("key fields")
		}
	}
	raw, _, e := safeRead(root, pathValue)
	if e != nil {
		return nil, nil, e
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("pem")
	}
	value, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, nil, e
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize || !sameJSON(carrier["spki"], identity(block.Bytes)) {
		return nil, nil, errors.New("spki")
	}
	return key, block.Bytes, nil
}
