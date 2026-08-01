package p1verify

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

type cborTag struct {
	Number uint64
	Value  any
}

type cborDecoder struct {
	raw []byte
	pos int
}

func decodeCBOR(raw []byte) (any, error) {
	d := &cborDecoder{raw: raw}
	v, err := d.one()
	if err != nil {
		return nil, err
	}
	if d.pos != len(raw) {
		return nil, errors.New("trailing bytes after CBOR item")
	}
	enc, err := encodeCBOR(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(enc, raw) {
		return nil, errors.New("non-deterministic CBOR encoding")
	}
	return v, nil
}

func (d *cborDecoder) read(n int) ([]byte, error) {
	if n < 0 || d.pos+n > len(d.raw) {
		return nil, errors.New("truncated CBOR")
	}
	out := d.raw[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

func (d *cborDecoder) ai(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		b, e := d.read(1)
		if e != nil {
			return 0, e
		}
		return uint64(b[0]), nil
	case ai == 25:
		b, e := d.read(2)
		if e != nil {
			return 0, e
		}
		return uint64(binary.BigEndian.Uint16(b)), nil
	case ai == 26:
		b, e := d.read(4)
		if e != nil {
			return 0, e
		}
		return uint64(binary.BigEndian.Uint32(b)), nil
	case ai == 27:
		b, e := d.read(8)
		if e != nil {
			return 0, e
		}
		return binary.BigEndian.Uint64(b), nil
	default:
		return 0, errors.New("indefinite or reserved CBOR encoding")
	}
}

func (d *cborDecoder) one() (any, error) {
	b, err := d.read(1)
	if err != nil {
		return nil, err
	}
	major, ai := b[0]>>5, b[0]&31
	if major == 7 {
		switch ai {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, errors.New("unsupported CBOR simple/float value")
	}
	n, err := d.ai(ai)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if n <= uint64(^uint64(0)>>1) {
			return int64(n), nil
		}
		return n, nil
	case 1:
		if n > uint64(^uint64(0)>>1) {
			return nil, errors.New("negative integer overflow")
		}
		return -1 - int64(n), nil
	case 2:
		return d.read(int(n))
	case 3:
		x, e := d.read(int(n))
		if e != nil {
			return nil, e
		}
		if !utf8.Valid(x) {
			return nil, errors.New("invalid CBOR UTF-8")
		}
		return string(x), nil
	case 4:
		a := make([]any, 0, int(n))
		for i := uint64(0); i < n; i++ {
			v, e := d.one()
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		return a, nil
	case 5:
		m := map[any]any{}
		for i := uint64(0); i < n; i++ {
			k, e := d.one()
			if e != nil {
				return nil, e
			}
			if !comparable(k) {
				return nil, errors.New("non-comparable CBOR map key")
			}
			if _, ok := m[k]; ok {
				return nil, errors.New("duplicate CBOR map key")
			}
			v, e := d.one()
			if e != nil {
				return nil, e
			}
			m[k] = v
		}
		return m, nil
	case 6:
		v, e := d.one()
		if e != nil {
			return nil, e
		}
		return cborTag{Number: n, Value: v}, nil
	default:
		return nil, fmt.Errorf("unsupported CBOR major type %d", major)
	}
}

func comparable(v any) bool {
	switch v.(type) {
	case string, int64, uint64, bool, nil:
		return true
	default:
		return false
	}
}

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n < 1<<32:
		b := make([]byte, 5)
		b[0] = major<<5 | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = major<<5 | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
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
			return head(0, uint64(x)), nil
		}
		return head(1, uint64(-1-x)), nil
	case uint64:
		return head(0, x), nil
	case []byte:
		return append(head(2, uint64(len(x))), x...), nil
	case string:
		b := []byte(x)
		return append(head(3, uint64(len(b))), b...), nil
	case []any:
		out := head(4, uint64(len(x)))
		for _, e := range x {
			b, err := encodeCBOR(e)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	case map[any]any:
		type pair struct{ k, v []byte }
		ps := make([]pair, 0, len(x))
		for k, v := range x {
			kb, e := encodeCBOR(k)
			if e != nil {
				return nil, e
			}
			vb, e := encodeCBOR(v)
			if e != nil {
				return nil, e
			}
			ps = append(ps, pair{kb, vb})
		}
		sort.Slice(ps, func(i, j int) bool {
			if len(ps[i].k) != len(ps[j].k) {
				return len(ps[i].k) < len(ps[j].k)
			}
			return bytes.Compare(ps[i].k, ps[j].k) < 0
		})
		out := head(5, uint64(len(ps)))
		for _, p := range ps {
			out = append(out, p.k...)
			out = append(out, p.v...)
		}
		return out, nil
	case cborTag:
		b, e := encodeCBOR(x.Value)
		if e != nil {
			return nil, e
		}
		return append(head(6, x.Number), b...), nil
	default:
		return nil, fmt.Errorf("unsupported CBOR type %T", v)
	}
}
