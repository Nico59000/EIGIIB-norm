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
const Route = "external-go-cose"

var windowsDrive = regexp.MustCompile(`^[A-Za-z]:`)

type Result struct {
	Standard   string  `json:"standard"`
	Route      string  `json:"route"`
	VectorID   string  `json:"vector_id"`
	Accepted   bool    `json:"accepted"`
	ErrorClass *string `json:"error_class"`
	Boundary   string  `json:"boundary"`
}

type portableReject struct {
	class string
	stage string
}

func (p portableReject) Error() string { return p.class }

func parseValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	opening, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	if opening == '{' {
		object := make(map[string]any)
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, ok := nameToken.(string)
			if !ok {
				return nil, errors.New("non-string object member")
			}
			if _, duplicate := object[name]; duplicate {
				return nil, fmt.Errorf("duplicate JSON member: %s", name)
			}
			member, err := parseValue(decoder)
			if err != nil {
				return nil, err
			}
			object[name] = member
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, errors.New("object close mismatch")
		}
		return object, nil
	}
	if opening == '[' {
		array := make([]any, 0)
		for decoder.More() {
			member, err := parseValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, member)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("array close mismatch")
		}
		return array, nil
	}
	return nil, errors.New("unexpected delimiter")
}

func ingest(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, portableReject{class: "syntax.invalid-utf8", stage: "utf8"}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, portableReject{class: "syntax.invalid-json", stage: "json"}
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, portableReject{class: "syntax.invalid-json", stage: "json"}
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, portableReject{class: "projection.invalid", stage: "projection"}
	}
	return object, nil
}

func lookup(object map[string]any, path ...string) (any, error) {
	var value any = object
	for _, name := range path {
		current, ok := value.(map[string]any)
		if !ok {
			return nil, portableReject{class: "projection.invalid", stage: "projection"}
		}
		next, exists := current[name]
		if !exists {
			return nil, portableReject{class: "projection.invalid", stage: "projection"}
		}
		value = next
	}
	return value, nil
}

func canonicalBase64(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, portableReject{class: "encoding.noncanonical-base64", stage: "base64"}
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, portableReject{class: "encoding.noncanonical-base64", stage: "base64"}
	}
	return decoded, nil
}

func safePortablePath(value any) error {
	text, ok := value.(string)
	if !ok || text == "" || strings.ContainsRune(text, '\x00') {
		return portableReject{class: "path.unsafe", stage: "path"}
	}
	if strings.HasPrefix(text, "/") || strings.HasPrefix(text, `\`) || windowsDrive.MatchString(text) || strings.Contains(text, `\`) {
		return portableReject{class: "path.unsafe", stage: "path"}
	}
	for _, segment := range strings.Split(text, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return portableReject{class: "path.unsafe", stage: "path"}
		}
	}
	return nil
}

func exactIdentity(value any, payload []byte) error {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 3 {
		return portableReject{class: "identity.length-mismatch", stage: "identity.length"}
	}
	if object["algorithm"] != "sha256" {
		return portableReject{class: "identity.digest-mismatch", stage: "identity.digest"}
	}
	number, ok := object["bytes"].(json.Number)
	if !ok {
		return portableReject{class: "identity.length-mismatch", stage: "identity.length"}
	}
	length, err := number.Int64()
	if err != nil || length != int64(len(payload)) {
		return portableReject{class: "identity.length-mismatch", stage: "identity.length"}
	}
	sum := sha256.Sum256(payload)
	digest, ok := object["digest"].(string)
	if !ok || digest != hex.EncodeToString(sum[:]) {
		return portableReject{class: "identity.digest-mismatch", stage: "identity.digest"}
	}
	return nil
}

func closedProjection(value any) error {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 7 {
		return portableReject{class: "projection.invalid", stage: "projection"}
	}
	required := []string{
		"manifest_binding_result",
		"p1a1_replay_result",
		"p1a2_replay_result",
		"p1a3_replay_result",
		"cross_capsule_binding_result",
		"end_to_end_result",
	}
	for _, name := range required {
		if object[name] != "conformant" {
			return portableReject{class: "projection.invalid", stage: "projection"}
		}
	}
	chain, ok := object["chain_identity"].(map[string]any)
	if !ok || len(chain) != 3 || chain["algorithm"] != "sha256" ||
		chain["digest"] != "8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d" {
		return portableReject{class: "projection.invalid", stage: "projection"}
	}
	number, ok := chain["bytes"].(json.Number)
	if !ok {
		return portableReject{class: "projection.invalid", stage: "projection"}
	}
	length, err := number.Int64()
	if err != nil || length != 2182 {
		return portableReject{class: "projection.invalid", stage: "projection"}
	}
	return nil
}

func Evaluate(raw []byte, vectorID string) Result {
	root, err := ingest(raw)
	var payload []byte
	if err == nil {
		var value any
		value, err = lookup(root, "payload", "base64")
		if err == nil {
			payload, err = canonicalBase64(value)
		}
	}
	if err == nil {
		var value any
		value, err = lookup(root, "payload", "path")
		if err == nil {
			err = safePortablePath(value)
		}
	}
	if err == nil {
		var value any
		value, err = lookup(root, "payload", "identity")
		if err == nil {
			err = exactIdentity(value, payload)
		}
	}
	if err == nil {
		var value any
		value, err = lookup(root, "projection")
		if err == nil {
			err = closedProjection(value)
		}
	}
	if err != nil {
		var rejected portableReject
		if errors.As(err, &rejected) {
			class := rejected.class
			return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: false, ErrorClass: &class, Boundary: rejected.stage}
		}
		class := "internal.unmapped"
		return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: false, ErrorClass: &class, Boundary: "internal"}
	}
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: true, ErrorClass: nil, Boundary: "projection"}
}
