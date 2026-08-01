package p1receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const Standard = "EIGIIB-P1-A7.6-1.0"
const Route = "independent-go-stdlib"

const (
	coseSign1Tag       = uint64(18)
	algorithmEdDSA     = int64(-8)
	receiptType        = "application/scitt-receipt+cose"
	transparencyIssuer = "https://eigiib.example/p1-a3/transparency-service"
	subject            = "urn:eigiib:p1-a2:dd14c7556ea261cee03c40615368511bf9360e5d7eae764804d7b426f4ed6da4"
)

type Result struct {
	Standard   string  `json:"standard"`
	Route      string  `json:"route"`
	VectorID   string  `json:"vector_id"`
	Accepted   bool    `json:"accepted"`
	ErrorClass *string `json:"error_class"`
	Boundary   string  `json:"boundary"`
}

func rejected(vectorID, class, boundary string) Result {
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: false, ErrorClass: &class, Boundary: boundary}
}
func accepted(vectorID string) Result {
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: true, Boundary: "receipt-root"}
}

func Evaluate(raw []byte, vectorID string) Result {
	carrier, err := readCarrier(raw)
	if err != nil {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-carrier")
	}
	value, err := decodeCBOR(carrier.ReceiptRaw)
	if err != nil {
		if errors.Is(err, errNonDeterministic) {
			return rejected(vectorID, "cbor.nondeterministic", "receipt-cbor-sign1")
		}
		return rejected(vectorID, "cose.invalid-structure", "receipt-cose-structure")
	}
	protectedRaw, proofRaw, signature, class, boundary := receiptParts(value, carrier.PublicDER)
	if class != "" {
		return rejected(vectorID, class, boundary)
	}
	sum := sha256.Sum256(carrier.SignedRaw)
	if len(carrier.SignedRaw) != expectedStatementBytes || hex.EncodeToString(sum[:]) != expectedStatementDigest {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-detached-binding")
	}
	proofTree, proofLeaf, path, class, boundary := decodeProof(proofRaw)
	if class != "" {
		return rejected(vectorID, class, boundary)
	}
	if proofTree != carrier.TreeSize || proofLeaf != carrier.LeafIndex {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-coordinates")
	}
	root, ok, coordinateFailure := inclusionRoot(carrier.SignedRaw, proofTree, proofLeaf, path)
	if coordinateFailure {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-coordinates")
	}
	if !ok {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-proof")
	}
	structure, err := encodeCBOR([]any{"Signature1", protectedRaw, []byte{}, root})
	if err != nil || !ed25519.Verify(carrier.PublicKey, structure, signature) {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-root")
	}
	return accepted(vectorID)
}
