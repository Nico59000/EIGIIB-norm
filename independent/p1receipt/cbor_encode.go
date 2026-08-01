package p1receipt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

func head(major byte, value uint64) []byte {
	switch {
	case value < 24:
		return []byte{major<<5 | byte(value)}
	case value < 256:
		return []byte{major<<5 | 24, byte(value)}
	case value < 65536:
		out := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(out[1:], uint16(value))
		return out
	case value < 1<<32:
		out := make([]byte, 5)
		out[0] = major<<5 | 26
		binary.BigEndian.PutUint32(out[1:], uint32(value))
		return out
	default:
		out := make([]byte, 9)
		out[0] = major<<5 | 27
		binary.BigEndian.PutUint64(out[1:], value)
		return out
	}
}

func encodeCBOR(value any) ([]byte, error) {
	switch current := value.(type) {
	case nil:
		return []byte{0xf6}, nil
	case bool:
		if current {
			return []byte{0xf5}, nil
		}
		return []byte{0xf4}, nil
	case int:
		return encodeCBOR(int64(current))
	case int64:
		if current >= 0 {
			return head(0, uint64(current)), nil
		}
		return head(1, uint64(-1-current)), nil
	case uint64:
		return head(0, current), nil
	case []byte:
		return append(head(2, uint64(len(current))), current...), nil
	case string:
		raw := []byte(current)
		return append(head(3, uint64(len(raw))), raw...), nil
	case []any:
		out := head(4, uint64(len(current)))
		for _, item := range current {
			encoded, err := encodeCBOR(item)
			if err != nil {
				return nil, err
			}
			out = append(out, encoded...)
		}
		return out, nil
	case map[any]any:
		type pair struct{ key, value []byte }
		pairs := make([]pair, 0, len(current))
		for key, member := range current {
			encodedKey, err := encodeCBOR(key)
			if err != nil {
				return nil, err
			}
			encodedValue, err := encodeCBOR(member)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, pair{encodedKey, encodedValue})
		}
		sort.Slice(pairs, func(i, j int) bool {
			if len(pairs[i].key) != len(pairs[j].key) {
				return len(pairs[i].key) < len(pairs[j].key)
			}
			return bytes.Compare(pairs[i].key, pairs[j].key) < 0
		})
		out := head(5, uint64(len(pairs)))
		for _, item := range pairs {
			out = append(out, item.key...)
			out = append(out, item.value...)
		}
		return out, nil
	case cborTag:
		encoded, err := encodeCBOR(current.Value)
		if err != nil {
			return nil, err
		}
		return append(head(6, current.Number), encoded...), nil
	default:
		return nil, fmt.Errorf("unsupported CBOR type %T", value)
	}
}
