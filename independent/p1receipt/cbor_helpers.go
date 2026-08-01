package p1receipt

import (
	"encoding/base64"
	"errors"
)

func lookupInt(mapping map[any]any, wanted int64) (any, bool) {
	if value, ok := mapping[wanted]; ok {
		return value, true
	}
	if wanted >= 0 {
		if value, ok := mapping[uint64(wanted)]; ok {
			return value, true
		}
	}
	return nil, false
}

func integer(value any) (int64, bool) {
	switch current := value.(type) {
	case int64:
		return current, true
	case uint64:
		if current <= uint64(^uint64(0)>>1) {
			return int64(current), true
		}
	}
	return 0, false
}

func equalInteger(value any, wanted int64) bool {
	observed, ok := integer(value)
	return ok && observed == wanted
}

func asBytes(value any) []byte {
	out, _ := value.([]byte)
	return out
}

func DecodeBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("non-canonical base64")
	}
	return raw, nil
}
