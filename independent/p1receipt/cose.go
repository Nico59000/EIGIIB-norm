package p1receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
)

func receiptParts(value any, der []byte) ([]byte, []byte, []byte, string, string) {
	tag, ok := value.(cborTag)
	if !ok || tag.Number != coseSign1Tag {
		return nil, nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	array, ok := tag.Value.([]any)
	if !ok || len(array) != 4 {
		return nil, nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	protectedRaw, ok := array[0].([]byte)
	if !ok {
		return nil, nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	unprotected, ok := array[1].(map[any]any)
	if !ok {
		return nil, nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	if array[2] != nil {
		return nil, nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	signature, ok := array[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		return nil, nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	protectedValue, err := decodeCBOR(protectedRaw)
	if err != nil {
		if errors.Is(err, errNonDeterministic) {
			return nil, nil, nil, "cbor.nondeterministic", "receipt-protected-header"
		}
		return nil, nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	protected, ok := protectedValue.(map[any]any)
	if !ok || !validHeaders(protected, der) {
		return nil, nil, nil, "cose.unsupported-header", "receipt-protected-header"
	}
	if len(unprotected) != 1 {
		return nil, nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofContainer, ok := lookupInt(unprotected, 396)
	if !ok {
		return nil, nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofMap, ok := proofContainer.(map[any]any)
	if !ok || len(proofMap) != 1 {
		return nil, nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofsValue, ok := lookupInt(proofMap, -1)
	if !ok {
		return nil, nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofs, ok := proofsValue.([]any)
	if !ok || len(proofs) != 1 {
		return nil, nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofRaw, ok := proofs[0].([]byte)
	if !ok {
		return nil, nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	return protectedRaw, proofRaw, signature, "", ""
}

func validHeaders(headers map[any]any, der []byte) bool {
	if len(headers) != 5 {
		return false
	}
	alg, ok := lookupInt(headers, 1)
	if !ok || !equalInteger(alg, algorithmEdDSA) {
		return false
	}
	kid, ok := lookupInt(headers, 4)
	expected := sha256.Sum256(der)
	if !ok || !bytes.Equal(asBytes(kid), expected[:]) {
		return false
	}
	claimsValue, ok := lookupInt(headers, 15)
	if !ok {
		return false
	}
	claims, ok := claimsValue.(map[any]any)
	if !ok || len(claims) != 2 {
		return false
	}
	iss, ok := lookupInt(claims, 1)
	if !ok || iss != transparencyIssuer {
		return false
	}
	sub, ok := lookupInt(claims, 2)
	if !ok || sub != subject {
		return false
	}
	typ, ok := lookupInt(headers, 16)
	if !ok || typ != receiptType {
		return false
	}
	vds, ok := lookupInt(headers, 395)
	if !ok || !equalInteger(vds, 1) {
		return false
	}
	allowed := map[int64]bool{1: true, 4: true, 15: true, 16: true, 395: true}
	for key := range headers {
		label, ok := integer(key)
		if !ok || !allowed[label] {
			return false
		}
	}
	return true
}
