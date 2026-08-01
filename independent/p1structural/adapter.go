package p1structural

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const Standard = "EIGIIB-P1-A7.3-1.0"
const Route = "independent-go-stdlib"

var drivePrefix = regexp.MustCompile(`^[A-Za-z]:`)

var projectionFields = map[string]struct{}{
	"manifest_binding_result":      {},
	"p1a1_replay_result":           {},
	"p1a2_replay_result":           {},
	"p1a3_replay_result":           {},
	"cross_capsule_binding_result": {},
	"end_to_end_result":            {},
	"chain_identity":               {},
}

type Result struct {
	Standard   string  `json:"standard"`
	Route      string  `json:"route"`
	VectorID   string  `json:"vector_id"`
	Accepted   bool    `json:"accepted"`
	ErrorClass *string `json:"error_class"`
	Boundary   string  `json:"boundary"`
}

type rejection struct {
	class    string
	boundary string
}

func (r rejection) Error() string         { return r.class }
func reject(class, boundary string) error { return rejection{class: class, boundary: boundary} }

func readJSONValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		out := map[string]any{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object key is not string")
			}
			if _, exists := out[key]; exists {
				return nil, fmt.Errorf("duplicate JSON member: %s", key)
			}
			value, err := readJSONValue(dec)
			if err != nil {
				return nil, err
			}
			out[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object terminator")
		}
		return out, nil
	case '[':
		out := []any{}
		for dec.More() {
			value, err := readJSONValue(dec)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array terminator")
		}
		return out, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func strictJSON(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, reject("syntax.invalid-utf8", "utf8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := readJSONValue(dec)
	if err != nil {
		return nil, reject("syntax.invalid-json", "json")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, reject("syntax.invalid-json", "json")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, reject("projection.invalid", "projection")
	}
	return root, nil
}

func nested(root map[string]any, keys ...string) (any, error) {
	var current any = root
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, reject("projection.invalid", "projection")
		}
		value, exists := object[key]
		if !exists {
			return nil, reject("projection.invalid", "projection")
		}
		current = value
	}
	return current, nil
}

func checkBase64(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, reject("encoding.noncanonical-base64", "base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, reject("encoding.noncanonical-base64", "base64")
	}
	return decoded, nil
}

func checkPath(value any) error {
	text, ok := value.(string)
	if !ok || text == "" || strings.ContainsRune(text, '\x00') {
		return reject("path.unsafe", "path")
	}
	if strings.HasPrefix(text, "/") || strings.HasPrefix(text, `\`) || drivePrefix.MatchString(text) || strings.Contains(text, `\`) {
		return reject("path.unsafe", "path")
	}
	for _, segment := range strings.Split(text, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return reject("path.unsafe", "path")
		}
	}
	return nil
}

func checkIdentity(value any, payload []byte) error {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 3 {
		return reject("identity.length-mismatch", "identity.length")
	}
	if object["algorithm"] != "sha256" {
		return reject("identity.digest-mismatch", "identity.digest")
	}
	lengthNumber, ok := object["bytes"].(json.Number)
	if !ok {
		return reject("identity.length-mismatch", "identity.length")
	}
	length, err := lengthNumber.Int64()
	if err != nil || length != int64(len(payload)) {
		return reject("identity.length-mismatch", "identity.length")
	}
	sum := sha256.Sum256(payload)
	digest, ok := object["digest"].(string)
	if !ok || digest != hex.EncodeToString(sum[:]) {
		return reject("identity.digest-mismatch", "identity.digest")
	}
	return nil
}

func checkProjection(value any) error {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(projectionFields) {
		return reject("projection.invalid", "projection")
	}
	for key := range projectionFields {
		if _, exists := object[key]; !exists {
			return reject("projection.invalid", "projection")
		}
	}
	for _, key := range []string{
		"manifest_binding_result",
		"p1a1_replay_result",
		"p1a2_replay_result",
		"p1a3_replay_result",
		"cross_capsule_binding_result",
		"end_to_end_result",
	} {
		if object[key] != "conformant" {
			return reject("projection.invalid", "projection")
		}
	}
	chain, ok := object["chain_identity"].(map[string]any)
	if !ok || len(chain) != 3 || chain["algorithm"] != "sha256" ||
		chain["digest"] != "8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d" {
		return reject("projection.invalid", "projection")
	}
	bytesNumber, ok := chain["bytes"].(json.Number)
	if !ok {
		return reject("projection.invalid", "projection")
	}
	n, err := bytesNumber.Int64()
	if err != nil || n != 2182 {
		return reject("projection.invalid", "projection")
	}
	return nil
}

func Evaluate(raw []byte, vectorID string) Result {
	root, err := strictJSON(raw)
	var payload []byte
	if err == nil {
		var value any
		value, err = nested(root, "payload", "base64")
		if err == nil {
			payload, err = checkBase64(value)
		}
	}
	if err == nil {
		var value any
		value, err = nested(root, "payload", "path")
		if err == nil {
			err = checkPath(value)
		}
	}
	if err == nil {
		var value any
		value, err = nested(root, "payload", "identity")
		if err == nil {
			err = checkIdentity(value, payload)
		}
	}
	if err == nil {
		var value any
		value, err = nested(root, "projection")
		if err == nil {
			err = checkProjection(value)
		}
	}
	if err != nil {
		var rejected rejection
		if errors.As(err, &rejected) {
			class := rejected.class
			return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: false, ErrorClass: &class, Boundary: rejected.boundary}
		}
		class := "internal.unmapped"
		return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: false, ErrorClass: &class, Boundary: "internal"}
	}
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: true, ErrorClass: nil, Boundary: "projection"}
}
