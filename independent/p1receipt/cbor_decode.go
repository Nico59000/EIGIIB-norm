package p1receipt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

func decodeCBOR(raw []byte) (any, error) {
	decoder := &cborDecoder{raw: raw}
	value, err := decoder.one()
	if err != nil {
		return nil, err
	}
	if decoder.pos != len(raw) {
		return nil, errors.New("trailing bytes after CBOR item")
	}
	encoded, err := encodeCBOR(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, raw) {
		return nil, errNonDeterministic
	}
	return value, nil
}

func (d *cborDecoder) read(count int) ([]byte, error) {
	if count < 0 || d.pos+count > len(d.raw) {
		return nil, errors.New("truncated CBOR")
	}
	out := d.raw[d.pos : d.pos+count]
	d.pos += count
	return out, nil
}

func (d *cborDecoder) argument(additional byte) (uint64, error) {
	switch {
	case additional < 24:
		return uint64(additional), nil
	case additional == 24:
		value, err := d.read(1)
		if err != nil {
			return 0, err
		}
		return uint64(value[0]), nil
	case additional == 25:
		value, err := d.read(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(value)), nil
	case additional == 26:
		value, err := d.read(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(value)), nil
	case additional == 27:
		value, err := d.read(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(value), nil
	default:
		return 0, errors.New("indefinite or reserved CBOR encoding")
	}
}

func (d *cborDecoder) one() (any, error) {
	initial, err := d.read(1)
	if err != nil {
		return nil, err
	}
	major, additional := initial[0]>>5, initial[0]&31
	if major == 7 {
		switch additional {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		default:
			return nil, errors.New("unsupported CBOR simple or float value")
		}
	}
	argument, err := d.argument(additional)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if argument <= uint64(^uint64(0)>>1) {
			return int64(argument), nil
		}
		return argument, nil
	case 1:
		if argument > uint64(^uint64(0)>>1) {
			return nil, errors.New("negative integer overflow")
		}
		return -1 - int64(argument), nil
	case 2:
		return d.read(int(argument))
	case 3:
		raw, err := d.read(int(argument))
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(raw) {
			return nil, errors.New("invalid CBOR UTF-8")
		}
		return string(raw), nil
	case 4:
		array := make([]any, 0, int(argument))
		for index := uint64(0); index < argument; index++ {
			item, err := d.one()
			if err != nil {
				return nil, err
			}
			array = append(array, item)
		}
		return array, nil
	case 5:
		mapping := map[any]any{}
		for index := uint64(0); index < argument; index++ {
			key, err := d.one()
			if err != nil {
				return nil, err
			}
			if !comparable(key) {
				return nil, errors.New("non-comparable CBOR map key")
			}
			if _, duplicate := mapping[key]; duplicate {
				return nil, errors.New("duplicate CBOR map key")
			}
			member, err := d.one()
			if err != nil {
				return nil, err
			}
			mapping[key] = member
		}
		return mapping, nil
	case 6:
		member, err := d.one()
		if err != nil {
			return nil, err
		}
		return cborTag{Number: argument, Value: member}, nil
	default:
		return nil, fmt.Errorf("unsupported CBOR major type %d", major)
	}
}

func comparable(value any) bool {
	switch value.(type) {
	case string, int64, uint64, bool, nil:
		return true
	default:
		return false
	}
}
