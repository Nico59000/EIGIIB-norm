package p1negative

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const Standard = "EIGIIB-P1-A7.2-1.0"
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
		return nil, portableReject{class: "internal.unmapped", stage: "shape"}
	}
	return object, nil
}

func lookup(object map[string]any, path ...string) (any, error) {
	var value any = object
	for _, name := range path {
		current, ok := value.(map[string]any)
		if !ok {
			return nil, portableReject{class: "internal.unmapped", stage: "shape"}
		}
		next, exists := current[name]
		if !exists {
			return nil, portableReject{class: "internal.unmapped", stage: "shape"}
		}
		value = next
	}
	return value, nil
}

func canonicalBase64(value any) error {
	text, ok := value.(string)
	if !ok {
		return portableReject{class: "encoding.noncanonical-base64", stage: "base64"}
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
		return portableReject{class: "encoding.noncanonical-base64", stage: "base64"}
	}
	return nil
}

func safePortablePath(value any) error {
	text, ok := value.(string)
	if !ok || text == "" || strings.ContainsRune(text, '\x00') {
		return portableReject{class: "path.unsafe", stage: "path"}
	}
	if strings.HasPrefix(text, "/") || strings.HasPrefix(text, `\`) || windowsDrive.MatchString(text) || strings.Contains(text, `\`) {
		return portableReject{class: "path.unsafe", stage: "path"}
	}
	segments := strings.Split(text, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return portableReject{class: "path.unsafe", stage: "path"}
		}
	}
	return nil
}

func Evaluate(raw []byte, vectorID string) Result {
	root, err := ingest(raw)
	if err == nil {
		var value any
		value, err = lookup(root, "payload", "base64")
		if err == nil {
			err = canonicalBase64(value)
		}
	}
	if err == nil {
		var value any
		value, err = lookup(root, "payload", "path")
		if err == nil {
			err = safePortablePath(value)
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
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: true, ErrorClass: nil, Boundary: "path"}
}
