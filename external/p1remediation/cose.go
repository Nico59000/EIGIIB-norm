package p1remediation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

func integer(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed), true
		}
	case int:
		return int64(typed), true
	case uint:
		return int64(typed), true
	}
	return 0, false
}

func lookup(values map[any]any, key int64) (any, bool) {
	if value, ok := values[key]; ok {
		return value, true
	}
	if key >= 0 {
		value, ok := values[uint64(key)]
		return value, ok
	}
	return nil, false
}

func equivalent(left, right any) bool {
	if li, ok := integer(left); ok {
		if ri, ok := integer(right); ok {
			return li == ri
		}
	}
	if lb, ok := left.([]byte); ok {
		rb, ok := right.([]byte)
		return ok && bytes.Equal(lb, rb)
	}
	return reflect.DeepEqual(left, right)
}

func canonicalCBOR(raw []byte) (any, bool) {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, false
	}
	var value any
	if err = cbor.Unmarshal(raw, &value); err != nil {
		return nil, false
	}
	encoded, err := mode.Marshal(value)
	return value, err == nil && bytes.Equal(encoded, raw)
}

func verifyCOSE(raw, payload []byte, contentType string, key ed25519.PublicKey, der []byte) error {
	value, ok := canonicalCBOR(raw)
	if !ok {
		return errors.New("noncanonical cose")
	}
	tag, ok := value.(cbor.Tag)
	if !ok || tag.Number != 18 {
		return errors.New("cose tag")
	}
	array, ok := tag.Content.([]any)
	if !ok || len(array) != 4 {
		return errors.New("cose structure")
	}
	protected, ok := array[0].([]byte)
	if !ok {
		return errors.New("protected")
	}
	unprotected, ok := array[1].(map[any]any)
	if !ok || len(unprotected) != 0 {
		return errors.New("unprotected")
	}
	gotPayload, ok := array[2].([]byte)
	if !ok || !bytes.Equal(gotPayload, payload) {
		return errors.New("payload")
	}
	signature, ok := array[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		return errors.New("signature")
	}
	protectedValue, ok := canonicalCBOR(protected)
	if !ok {
		return errors.New("protected canonical")
	}
	protectedMap, ok := protectedValue.(map[any]any)
	if !ok || len(protectedMap) != 3 {
		return errors.New("protected map")
	}
	algorithm, a := lookup(protectedMap, 1)
	content, c := lookup(protectedMap, 3)
	kid, k := lookup(protectedMap, 4)
	if !a || !c || !k {
		return errors.New("protected fields")
	}
	algorithmValue, ok := integer(algorithm)
	if !ok || algorithmValue != -8 {
		return errors.New("algorithm")
	}
	contentValue, ok := content.(string)
	if !ok || contentValue != contentType {
		return errors.New("content type")
	}
	kidBytes, ok := kid.([]byte)
	expectedKid := sha256.Sum256(der)
	if !ok || !bytes.Equal(kidBytes, expectedKid[:]) {
		return errors.New("kid")
	}
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(raw); err != nil {
		return err
	}
	if !bytes.Equal(message.Payload, payload) {
		return errors.New("go-cose payload")
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, key)
	if err != nil {
		return err
	}
	return message.Verify(nil, verifier)
}
