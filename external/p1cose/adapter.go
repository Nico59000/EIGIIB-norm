package p1cose

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const Standard = "EIGIIB-P1-A7.5-1.0"
const Route = "external-go-cose"

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
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-structure")
	}
	var value any
	if err := cbor.Unmarshal(raw, &value); err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-structure")
	}
	canonical, err := mode.Marshal(value)
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-structure")
	}
	if !bytes.Equal(canonical, raw) {
		return rejected(vectorID, "cbor.nondeterministic", "cbor-sign1")
	}
	protectedRaw, payload, reject := sign1Parts(value)
	if reject != nil {
		return rejected(vectorID, reject.class, reject.boundary)
	}
	var protectedValue any
	if err := cbor.Unmarshal(protectedRaw, &protectedValue); err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-protected-header")
	}
	protectedCanonical, err := mode.Marshal(protectedValue)
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-protected-header")
	}
	if !bytes.Equal(protectedCanonical, protectedRaw) {
		return rejected(vectorID, "cbor.nondeterministic", "cbor-protected-header")
	}
	protectedMap, ok := asMap(protectedValue)
	if !ok {
		return rejected(vectorID, "cose.invalid-structure", "cose-protected-header")
	}
	var payloadValue any
	if err := cbor.Unmarshal(payload, &payloadValue); err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-payload")
	}
	payloadCanonical, err := mode.Marshal(payloadValue)
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-payload")
	}
	if !bytes.Equal(payloadCanonical, payload) {
		return rejected(vectorID, "cbor.nondeterministic", "cbor-payload")
	}
	if reject = requireHeaders(protectedMap, der); reject != nil {
		return rejected(vectorID, reject.class, reject.boundary)
	}

	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(raw); err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-structure")
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pk)
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "cose-structure")
	}
	if err := message.Verify(nil, verifier); err != nil {
		return rejected(vectorID, "signature.invalid", "cose-signature")
	}
	return accepted(vectorID)
}

func sign1Parts(value any) ([]byte, []byte, *portableReject) {
	tag, ok := value.(cbor.Tag)
	if !ok || tag.Number != coseSign1Tag {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, &r
	}
	array, ok := tag.Content.([]any)
	if !ok || len(array) != 4 {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, &r
	}
	protected, ok := array[0].([]byte)
	if !ok {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, &r
	}
	unprotected, ok := asMap(array[1])
	if !ok || len(unprotected) != 0 {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, &r
	}
	payload, ok := array[2].([]byte)
	if !ok {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, &r
	}
	signature, ok := array[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		r := portableReject{"cose.invalid-structure", "cose-structure"}
		return nil, nil, &r
	}
	return protected, payload, nil
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
	claims, okMap := asMap(claimsValue)
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

func asMap(value any) (map[any]any, bool) {
	switch current := value.(type) {
	case map[any]any:
		return current, true
	default:
		return nil, false
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
	case int:
		return int64(current), true
	case int8:
		return int64(current), true
	case int16:
		return int64(current), true
	case int32:
		return int64(current), true
	case int64:
		return current, true
	case uint:
		return int64(current), true
	case uint8:
		return int64(current), true
	case uint16:
		return int64(current), true
	case uint32:
		return int64(current), true
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
