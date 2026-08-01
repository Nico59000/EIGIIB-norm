package p1remediation

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
	a, ok := tag.Value.([]any)
	if !ok || len(a) != 4 {
		return errors.New("cose structure")
	}
	protected, ok := a[0].([]byte)
	if !ok {
		return errors.New("protected")
	}
	unp, ok := a[1].([]mapEntry)
	if !ok || len(unp) != 0 {
		return errors.New("unprotected")
	}
	got, ok := a[2].([]byte)
	if !ok || !bytes.Equal(got, payload) {
		return errors.New("payload")
	}
	sig, ok := a[3].([]byte)
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
	alg, aok := mapLookup(pm, 1)
	ct, cok := mapLookup(pm, 3)
	kid, kok := mapLookup(pm, 4)
	if !aok || !cok || !kok {
		return errors.New("protected fields")
	}
	av, ok := alg.(int64)
	if !ok || av != -8 {
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
	to, e := encodeCBOR([]any{"Signature1", protected, []byte{}, payload})
	if e != nil {
		return e
	}
	if !ed25519.Verify(key, to, sig) {
		return errors.New("ed25519")
	}
	return nil
}
