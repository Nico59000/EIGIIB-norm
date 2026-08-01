package p1receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const Standard = "EIGIIB-P1-A7.6-1.0"
const Route = "external-go-cose"
const CarrierStandard = "EIGIIB-P1-A7.6-CARRIER-1.0"
const Profile = "receipt-detached-proof-root-negative-replay-v1"
const expectedStatementDigest = "27c960d31e9afbf454c8bb6dbdd396309b3dec629f58d8f5c87553864e579d81"
const expectedStatementBytes = 396
const transparencyIssuer = "https://eigiib.example/p1-a3/transparency-service"
const subject = "urn:eigiib:p1-a2:dd14c7556ea261cee03c40615368511bf9360e5d7eae764804d7b426f4ed6da4"
const receiptType = "application/scitt-receipt+cose"

type Result struct {
	Standard   string  `json:"standard"`
	Route      string  `json:"route"`
	VectorID   string  `json:"vector_id"`
	Accepted   bool    `json:"accepted"`
	ErrorClass *string `json:"error_class"`
	Boundary   string  `json:"boundary"`
}

type identityCarrier struct {
	Algorithm string `json:"algorithm"`
	Bytes     int    `json:"bytes"`
	Digest    string `json:"digest"`
}
type dataCarrier struct {
	Data     string          `json:"data"`
	Identity identityCarrier `json:"identity"`
}
type bindingCarrier struct {
	TreeSize                int64           `json:"treeSize"`
	LeafIndex               int64           `json:"leafIndex"`
	SignedStatementIdentity identityCarrier `json:"signedStatementIdentity"`
}
type carrier struct {
	Standard        string         `json:"standard"`
	Profile         string         `json:"profile"`
	Binding         bindingCarrier `json:"binding"`
	SignedStatement dataCarrier    `json:"signedStatement"`
	Receipt         dataCarrier    `json:"receipt"`
	PublicKeyPEM    string         `json:"publicKeyPem"`
}

func rejected(vectorID, class, boundary string) Result {
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: false, ErrorClass: &class, Boundary: boundary}
}
func accepted(vectorID string) Result {
	return Result{Standard: Standard, Route: Route, VectorID: vectorID, Accepted: true, Boundary: "receipt-root"}
}

func Evaluate(raw []byte, vectorID string) Result {
	c, signedRaw, receiptRaw, publicKey, der, err := readCarrier(raw)
	if err != nil {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-carrier")
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "receipt-cose-structure")
	}
	var value any
	if err := cbor.Unmarshal(receiptRaw, &value); err != nil {
		return rejected(vectorID, "cose.invalid-structure", "receipt-cose-structure")
	}
	canonical, err := mode.Marshal(value)
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "receipt-cose-structure")
	}
	if !bytes.Equal(canonical, receiptRaw) {
		return rejected(vectorID, "cbor.nondeterministic", "receipt-cbor-sign1")
	}
	protectedRaw, proofRaw, rejectClass, rejectBoundary := receiptParts(value, der, mode)
	if rejectClass != "" {
		return rejected(vectorID, rejectClass, rejectBoundary)
	}
	sum := sha256.Sum256(signedRaw)
	if len(signedRaw) != expectedStatementBytes || hex.EncodeToString(sum[:]) != expectedStatementDigest {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-detached-binding")
	}
	tree, leaf, path, rejectClass, rejectBoundary := decodeProof(proofRaw, mode)
	if rejectClass != "" {
		return rejected(vectorID, rejectClass, rejectBoundary)
	}
	if tree != c.Binding.TreeSize || leaf != c.Binding.LeafIndex {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-coordinates")
	}
	root, proofOK, coordinatesOK := inclusionRoot(signedRaw, tree, leaf, path)
	if !coordinatesOK {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-coordinates")
	}
	if !proofOK {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-proof")
	}
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(receiptRaw); err != nil {
		return rejected(vectorID, "cose.invalid-structure", "receipt-cose-structure")
	}
	message.Payload = root
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, publicKey)
	if err != nil {
		return rejected(vectorID, "cose.invalid-structure", "receipt-cose-structure")
	}
	if err := message.Verify(nil, verifier); err != nil {
		return rejected(vectorID, "receipt.invalid-proof", "receipt-root")
	}
	_ = protectedRaw
	return accepted(vectorID)
}
