package p1time

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
)

func verifyCOSE(raw, payload []byte, contentType string, key ed25519.PublicKey, der []byte) error {
	v, e := decodeCBOR(raw)
	if e != nil {
		return e
	}
	tag, ok := v.(cborTag)
	if !ok || tag.Number != 18 {
		return errors.New("cose tag")
	}
	arr, ok := tag.Value.([]any)
	if !ok || len(arr) != 4 {
		return errors.New("cose structure")
	}
	protected, ok := arr[0].([]byte)
	if !ok {
		return errors.New("protected")
	}
	unp, ok := arr[1].([]mapEntry)
	if !ok || len(unp) != 0 {
		return errors.New("unprotected")
	}
	gotPayload, ok := arr[2].([]byte)
	if !ok || !bytes.Equal(gotPayload, payload) {
		return errors.New("payload")
	}
	sig, ok := arr[3].([]byte)
	if !ok || len(sig) != ed25519.SignatureSize {
		return errors.New("signature")
	}
	pv, e := decodeCBOR(protected)
	if e != nil {
		return e
	}
	pm, ok := pv.([]mapEntry)
	if !ok || len(pm) != 3 {
		return errors.New("protected map")
	}
	alg, a := mapLookup(pm, 1)
	ct, c := mapLookup(pm, 3)
	kid, k := mapLookup(pm, 4)
	if !a || !c || !k {
		return errors.New("protected fields")
	}
	algv, ok := alg.(int64)
	if !ok || algv != -8 {
		return errors.New("algorithm")
	}
	cts, ok := ct.(string)
	if !ok || cts != contentType {
		return errors.New("content type")
	}
	kidb, ok := kid.([]byte)
	sum := sha256.Sum256(der)
	if !ok || !bytes.Equal(kidb, sum[:]) {
		return errors.New("kid")
	}
	toVerify, e := encodeCBOR([]any{"Signature1", protected, []byte{}, payload})
	if e != nil {
		return e
	}
	if !ed25519.Verify(key, toVerify, sig) {
		return errors.New("ed25519")
	}
	return nil
}
