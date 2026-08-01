package p1cose

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

const Standard = "EIGIIB-P1-A7.5-1.0"
const Route = "independent-go-stdlib"

const (
	coseSign1Tag   = uint64(18)
	algorithmEdDSA = int64(-8)
	issuer         = "https://eigiib.example/p1-a3/issuer"
	contentType    = "application/cbor"
	messageType    = "application/scitt-statement+cose"
)

type Result struct {
	Standard   string  `json:"standard"`
	Route      string  `json:"route"`
	VectorID   string  `json:"vector_id"`
	Accepted   bool    `json:"accepted"`
	ErrorClass *string `json:"error_class"`
	Boundary   string  `json:"boundary"`
}

type portableReject struct {
	class    string
	boundary string
}

func (p portableReject) Error() string { return p.class }

type cborTag struct {
	Number uint64
	Value  any
}

type cborDecoder struct {
	raw []byte
	pos int
}

func rejected(vectorID, class, boundary string) Result {
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: false, ErrorClass: &class, Boundary: boundary}
}

func accepted(vectorID string) Result {
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: true, ErrorClass: nil, Boundary: "cose-signature"}
}

func Evaluate(raw, publicKeyPEM []byte, vectorID string) Result {
	pk, der, err := readEd25519(publicKeyPEM)
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-structure")
	}
	value, err := decodeCBOR(raw)
	if err != nil {
		if errors.Is(err, errNonDeterministic) {
			return rejected(vectorID, "cbor.nondeterministic", "cbor-sign1")
		}
		return rejected(vectorID, "cose.invalid-structure", "cose-structure")
	}
	protectedRaw, _, payload, signature, reject := sign1Parts(value)
	if reject != nil {
		return rejected(vectorID, reject.class, reject.boundary)
	}
	protectedValue, err := decodeCBOR(protectedRaw)
	if err != nil {
		if errors.Is(err, errNonDeterministic) {
			return rejected(vectorID, "cbor.nondeterministic", "cbor-protected-header")
		}
		return rejected(vectorID, "cose.invalid-structure", "cose-protected-header")
	}
	protectedMap, ok := protectedValue.(map[any]any)
	if !ok {
		return rejected(vectorID, "cose.invalid-structure", "cose-protected-header")
	}
	if _, err := decodeCBOR(payload); err != nil {
		if errors.Is(err, errNonDeterministic) {
			return rejected(vectorID, "cbor.nondeterministic", "cbor-payload")
		}
		return rejected(vectorID, "cose.invalid-structure", "cose-payload")
	}
	if reject = requireHeaders(protectedMap, der); reject != nil {
		return rejected(vectorID, reject.class, reject.boundary)
	}
	message, err := encodeCBOR([]any{"Signature1", protectedRaw, []byte{}, payload})
	if err != nil || !ed25519.Verify(pk, message, signature) {
		return rejected(vectorID, "signature.invalid", "cose-signature")
	}
	return accepted(vectorID)
}

func sign1Parts(value any) ([]byte, map[any]any, []byte, []byte, *portableReject) {
	tag, ok := value.(cborTag)
	if !ok || tag.Number != coseSign1Tag {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, nil, nil, &r
	}
	array, ok := tag.Value.([]any)
	if !ok || len(array) != 4 {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, nil, nil, &r
	}
	protected, ok := array[0].([]byte)
	if !ok {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, nil, nil, &r
	}
	unprotected, ok := array[1].(map[any]any)
	if !ok || len(unprotected) != 0 {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, nil, nil, &r
	}
	payload, ok := array[2].([]byte)
	if !ok {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, nil, nil, &r
	}
	signature, ok := array[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, nil, nil, &r
	}
	return protected, unprotected, payload, signature, nil
}

func requireHeaders(headers map[any]any, der []byte) *portableReject {
	if critical, ok := lookupInt(headers, 2); ok {
		labels, ok := critical.([]any)
		if !ok || len(labels) == 0 {
			r := portableReject{"cose.invalid-structure", "cose-protected-header"}
			return &r
		}
		supported := map[int64]bool{1: true, 3: true, 4: true, 15: true, 16: true}
		for _, item := range labels {
			label, ok := integer(item)
			if !ok {
				r := portableReject{"cose.invalid-structure", "cose-protected-header"}
				return &r
			}
			if !supported[label] {
				r := portableReject{"cose.unsupported-header", "cose-protected-header"}
				return &r
			}
		}
	}
	algorithm, ok := lookupInt(headers, 1)
	if !ok || !equalInteger(algorithm, algorithmEdDSA) {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	content, ok := lookupInt(headers, 3)
	if !ok || content != contentType {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	kid, ok := lookupInt(headers, 4)
	expectedKid := sha256.Sum256(der)
	if !ok || !bytes.Equal(asBytes(kid), expectedKid[:]) {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	claimsValue, ok := lookupInt(headers, 15)
	claims, okMap := claimsValue.(map[any]any)
	if !ok || !okMap || len(claims) != 2 {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	iss, ok := lookupInt(claims, 1)
	if !ok || iss != issuer {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	sub, ok := lookupInt(claims, 2)
	if !ok {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	if _, ok := sub.(string); !ok {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	message, ok := lookupInt(headers, 16)
	if !ok || message != messageType {
		r := portableReject{"cose.unsupported-header", "cose-protected-header"}
		return &r
	}
	allowed := map[int64]bool{1: true, 2: true, 3: true, 4: true, 15: true, 16: true}
	for key := range headers {
		label, ok := integer(key)
		if !ok || !allowed[label] {
			r := portableReject{"cose.unsupported-header", "cose-protected-header"}
			return &r
		}
	}
	return nil
}

func readEd25519(raw []byte) (ed25519.PublicKey, []byte, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("invalid public key PEM")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pk, ok := value.(ed25519.PublicKey)
	if !ok || len(pk) != ed25519.PublicKeySize || len(block.Bytes) != 44 {
		return nil, nil, errors.New("key is not Ed25519 SPKI")
	}
	return pk, block.Bytes, nil
}

var errNonDeterministic = errors.New("non-deterministic CBOR encoding")

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
