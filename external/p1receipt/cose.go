package p1receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

func receiptParts(value any, der []byte, mode cbor.EncMode) ([]byte, []byte, string, string) {
	tag, ok := value.(cbor.Tag)
	if !ok || tag.Number != 18 {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	array, ok := tag.Content.([]any)
	if !ok || len(array) != 4 {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	protectedRaw, ok := array[0].([]byte)
	if !ok {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	unprotected, ok := asMap(array[1])
	if !ok {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	if array[2] != nil {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	signature, ok := array[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	var protectedValue any
	if err := cbor.Unmarshal(protectedRaw, &protectedValue); err != nil {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	canonical, err := mode.Marshal(protectedValue)
	if err != nil {
		return nil, nil, "cose.invalid-structure", "receipt-cose-structure"
	}
	if !bytes.Equal(canonical, protectedRaw) {
		return nil, nil, "cbor.nondeterministic", "receipt-protected-header"
	}
	protected, ok := asMap(protectedValue)
	if !ok || !validHeaders(protected, der) {
		return nil, nil, "cose.unsupported-header", "receipt-protected-header"
	}
	if len(unprotected) != 1 {
		return nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofContainer, ok := lookupInt(unprotected, 396)
	if !ok {
		return nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofMap, ok := asMap(proofContainer)
	if !ok || len(proofMap) != 1 {
		return nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofsValue, ok := lookupInt(proofMap, -1)
	if !ok {
		return nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofs, ok := proofsValue.([]any)
	if !ok || len(proofs) != 1 {
		return nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	proofRaw, ok := proofs[0].([]byte)
	if !ok {
		return nil, nil, "receipt.invalid-proof", "receipt-proof"
	}
	return protectedRaw, proofRaw, "", ""
}

func validHeaders(headers map[any]any, der []byte) bool {
	if len(headers) != 5 {
		return false
	}
	alg, ok := lookupInt(headers, 1)
	if !ok || !equalInteger(alg, -8) {
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
	claims, ok := asMap(claimsValue)
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

func asMap(value any) (map[any]any, bool) { m, ok := value.(map[any]any); return m, ok }
func lookupInt(mapping map[any]any, wanted int64) (any, bool) {
	if v, ok := mapping[wanted]; ok {
		return v, true
	}
	if wanted >= 0 {
		if v, ok := mapping[uint64(wanted)]; ok {
			return v, true
		}
	}
	return nil, false
}
func integer(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		return int64(v), true
	case uint8:
		return int64(v), true
	case uint16:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint64:
		if v <= uint64(^uint64(0)>>1) {
			return int64(v), true
		}
	}
	return 0, false
}
func equalInteger(value any, wanted int64) bool { v, ok := integer(value); return ok && v == wanted }
func asBytes(value any) []byte                  { v, _ := value.([]byte); return v }
