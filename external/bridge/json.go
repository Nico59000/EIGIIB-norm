package bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func strictJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := decodeJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func decodeJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch delim := tok.(type) {
	case json.Delim:
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
					return nil, fmt.Errorf("JSON object key is not a string")
				}
				if _, exists := out[key]; exists {
					return nil, fmt.Errorf("duplicate JSON member: %s", key)
				}
				value, err := decodeJSONValue(dec)
				if err != nil {
					return nil, err
				}
				out[key] = value
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("invalid JSON object termination")
			}
			return out, nil
		case '[':
			out := []any{}
			for dec.More() {
				value, err := decodeJSONValue(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("invalid JSON array termination")
			}
			return out, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
	case nil, bool, string, json.Number:
		return tok, nil
	default:
		return nil, fmt.Errorf("unsupported JSON token %T", tok)
	}
}
