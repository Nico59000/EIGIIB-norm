package p1transparency

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

type cborTag struct {
	Number uint64
	Value  any
}
type mapEntry struct {
	key, value any
	encodedKey []byte
}

type cborDecoder struct {
	raw []byte
	off int
}

func (d *cborDecoder) take(n int) ([]byte, error) {
	if n < 0 || d.off+n > len(d.raw) {
		return nil, errors.New("truncated cbor")
	}
	out := d.raw[d.off : d.off+n]
	d.off += n
	return out, nil
}
func (d *cborDecoder) uint(ai byte) (uint64, error) {
	if ai < 24 {
		return uint64(ai), nil
	}
	sizes := map[byte]int{24: 1, 25: 2, 26: 4, 27: 8}
	n, ok := sizes[ai]
	if !ok {
		return 0, errors.New("indefinite cbor")
	}
	raw, e := d.take(n)
	if e != nil {
		return 0, e
	}
	var v uint64
	switch n {
	case 1:
		v = uint64(raw[0])
	case 2:
		v = uint64(binary.BigEndian.Uint16(raw))
	case 4:
		v = uint64(binary.BigEndian.Uint32(raw))
	case 8:
		v = binary.BigEndian.Uint64(raw)
	}
	if (ai == 24 && v < 24) || (ai == 25 && v <= 255) || (ai == 26 && v <= 65535) || (ai == 27 && v <= 4294967295) {
		return 0, errors.New("nonminimal cbor")
	}
	return v, nil
}
func comparableKey(v any) string {
	switch x := v.(type) {
	case int64:
		return fmt.Sprintf("i:%d", x)
	case uint64:
		return fmt.Sprintf("u:%d", x)
	case string:
		return "s:" + x
	default:
		return fmt.Sprintf("%T:%v", v, v)
	}
}
func (d *cborDecoder) item() (any, error) {
	b, e := d.take(1)
	if e != nil {
		return nil, e
	}
	major, ai := b[0]>>5, b[0]&31
	switch major {
	case 0:
		v, e := d.uint(ai)
		return v, e
	case 1:
		v, e := d.uint(ai)
		if e != nil {
			return nil, e
		}
		if v > uint64(^uint64(0)>>1) {
			return nil, errors.New("negative range")
		}
		return int64(-1 - int64(v)), nil
	case 2, 3:
		n, e := d.uint(ai)
		if e != nil {
			return nil, e
		}
		raw, e := d.take(int(n))
		if e != nil {
			return nil, e
		}
		if major == 2 {
			return append([]byte{}, raw...), nil
		}
		return string(raw), nil
	case 4:
		n, e := d.uint(ai)
		if e != nil {
			return nil, e
		}
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			v, e := d.item()
			if e != nil {
				return nil, e
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		n, e := d.uint(ai)
		if e != nil {
			return nil, e
		}
		out := make([]mapEntry, 0, n)
		seen := map[string]bool{}
		var prev []byte
		for i := uint64(0); i < n; i++ {
			start := d.off
			k, e := d.item()
			if e != nil {
				return nil, e
			}
			enc := append([]byte{}, d.raw[start:d.off]...)
			sk := comparableKey(k)
			if seen[sk] {
				return nil, errors.New("duplicate cbor key")
			}
			seen[sk] = true
			if prev != nil && (len(prev) > len(enc) || (len(prev) == len(enc) && bytes.Compare(prev, enc) >= 0)) {
				return nil, errors.New("cbor map order")
			}
			prev = enc
			v, e := d.item()
			if e != nil {
				return nil, e
			}
			out = append(out, mapEntry{k, v, enc})
		}
		return out, nil
	case 6:
		n, e := d.uint(ai)
		if e != nil {
			return nil, e
		}
		v, e := d.item()
		return cborTag{n, v}, e
	case 7:
		if ai == 20 {
			return false, nil
		}
		if ai == 21 {
			return true, nil
		}
		if ai == 22 {
			return nil, nil
		}
	}
	return nil, errors.New("unsupported cbor")
}

func cborHead(major byte, n uint64) []byte {
	p := major << 5
	if n < 24 {
		return []byte{p | byte(n)}
	}
	if n <= 255 {
		return []byte{p | 24, byte(n)}
	}
	if n <= 65535 {
		b := make([]byte, 3)
		b[0] = p | 25
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	}
	if n <= 4294967295 {
		b := make([]byte, 5)
		b[0] = p | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
	b := make([]byte, 9)
	b[0] = p | 27
	binary.BigEndian.PutUint64(b[1:], n)
	return b
}
func encodeCBOR(v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return []byte{0xf6}, nil
	case bool:
		if x {
			return []byte{0xf5}, nil
		}
		return []byte{0xf4}, nil
	case int:
		return encodeCBOR(int64(x))
	case int64:
		if x >= 0 {
			return cborHead(0, uint64(x)), nil
		}
		return cborHead(1, uint64(-1-x)), nil
	case uint64:
		return cborHead(0, x), nil
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...), nil
	case string:
		b := []byte(x)
		return append(cborHead(3, uint64(len(b))), b...), nil
	case []any:
		out := cborHead(4, uint64(len(x)))
		for _, item := range x {
			b, e := encodeCBOR(item)
			if e != nil {
				return nil, e
			}
			out = append(out, b...)
		}
		return out, nil
	case []mapEntry:
		rows := append([]mapEntry{}, x...)
		sort.Slice(rows, func(i, j int) bool {
			if len(rows[i].encodedKey) != len(rows[j].encodedKey) {
				return len(rows[i].encodedKey) < len(rows[j].encodedKey)
			}
			return bytes.Compare(rows[i].encodedKey, rows[j].encodedKey) < 0
		})
		out := cborHead(5, uint64(len(rows)))
		for _, r := range rows {
			kb, e := encodeCBOR(r.key)
			if e != nil {
				return nil, e
			}
			vb, e := encodeCBOR(r.value)
			if e != nil {
				return nil, e
			}
			out = append(out, kb...)
			out = append(out, vb...)
		}
		return out, nil
	case cborTag:
		b, e := encodeCBOR(x.Value)
		if e != nil {
			return nil, e
		}
		return append(cborHead(6, x.Number), b...), nil
	}
	return nil, fmt.Errorf("unsupported cbor type %T", v)
}
func decodeCBOR(raw []byte) (any, error) {
	d := &cborDecoder{raw: raw}
	v, e := d.item()
	if e != nil {
		return nil, e
	}
	if d.off != len(raw) {
		return nil, errors.New("trailing cbor")
	}
	enc, e := encodeCBOR(v)
	if e != nil || !bytes.Equal(enc, raw) {
		return nil, errors.New("noncanonical cbor")
	}
	return v, nil
}
func mapLookup(rows []mapEntry, key int64) (any, bool) {
	for _, r := range rows {
		switch k := r.key.(type) {
		case int64:
			if k == key {
				return r.value, true
			}
		case uint64:
			if key >= 0 && k == uint64(key) {
				return r.value, true
			}
		}
	}
	return nil, false
}
