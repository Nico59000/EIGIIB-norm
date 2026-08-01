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
const Route = "independent-go-stdlib"

var drivePrefix = regexp.MustCompile(`^[A-Za-z]:`)

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

func (r rejection) Error() string { return r.class }
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
		return nil, reject("internal.unmapped", "shape")
	}
	return root, nil
}

func nested(root map[string]any, keys ...string) (any, error) {
	var current any = root
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, reject("internal.unmapped", "shape")
		}
		value, exists := object[key]
		if !exists {
			return nil, reject("internal.unmapped", "shape")
		}
		current = value
	}
	return current, nil
}

func checkBase64(value any) error {
	text, ok := value.(string)
	if !ok {
		return reject("encoding.noncanonical-base64", "base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
		return reject("encoding.noncanonical-base64", "base64")
	}
	return nil
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

func Evaluate(raw []byte, vectorID string) Result {
	root, err := strictJSON(raw)
	if err == nil {
		var value any
		value, err = nested(root, "payload", "base64")
		if err == nil {
			err = checkBase64(value)
		}
	}
	if err == nil {
		var value any
		value, err = nested(root, "payload", "path")
		if err == nil {
			err = checkPath(value)
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
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: true, ErrorClass: nil, Boundary: "path"}
}
