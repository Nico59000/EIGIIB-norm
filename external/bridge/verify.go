package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"

	"eigiib.example/independent/p1verify"
	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const (
	Standard         = "EIGIIB-P1-A6-1.0"
	ToolVersion      = "0.1.0"
	Implementation   = "veraison-go-cose-v1.3.0"
	ObservationScope = "p1-a3-cose-sign1-and-receipt"
)

const (
	signedStatementMedia = "application/scitt-statement+cose"
	receiptMedia          = "application/scitt-receipt+cose"
	bundleMedia           = "application/vnd.dev.sigstore.bundle.v0.3+json"
	issuerID              = "https://eigiib.example/p1-a3/issuer"
	transparencyServiceID = "https://eigiib.example/p1-a3/transparency-service"
)

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type Result struct {
	Tool                             string            `json:"tool"`
	ToolVersion                      string            `json:"tool_version"`
	Standard                         string            `json:"standard"`
	Implementation                   string            `json:"implementation"`
	ObservationScope                 string            `json:"observation_scope"`
	StructuralResult                 string            `json:"structural_result"`
	BaselineRouteResult              string            `json:"baseline_route_result"`
	ExternalObservationResult        string            `json:"external_observation_result"`
	ExternalLibraryResult            string            `json:"external_library_result"`
	ManifestBindingResult            string            `json:"manifest_binding_result"`
	P1A1ReplayResult                 string            `json:"p1a1_replay_result"`
	P1A2ReplayResult                 string            `json:"p1a2_replay_result"`
	P1A3ReplayResult                 string            `json:"p1a3_replay_result"`
	CrossCapsuleBindingResult        string            `json:"cross_capsule_binding_result"`
	EndToEndResult                   string            `json:"end_to_end_result"`
	ChainIdentity                    p1verify.Identity `json:"chain_identity"`
	TrustResult                      string            `json:"trust_result"`
	ProductionInteroperabilityResult string            `json:"production_interoperability_result"`
	Findings                         []Finding         `json:"findings"`
}

func Verify(root string) Result {
	baseline := p1verify.Verify(root)
	result := Result{
		Tool:                             "eigiib-external-native-bridge",
		ToolVersion:                      ToolVersion,
		Standard:                         Standard,
		Implementation:                   Implementation,
		ObservationScope:                 ObservationScope,
		StructuralResult:                 "non-conformant",
		BaselineRouteResult:              "invalid",
		ExternalObservationResult:        "not-evaluated",
		ExternalLibraryResult:            "not-evaluated",
		ManifestBindingResult:            baseline.ManifestBindingResult,
		P1A1ReplayResult:                 baseline.P1A1ReplayResult,
		P1A2ReplayResult:                 baseline.P1A2ReplayResult,
		P1A3ReplayResult:                 baseline.P1A3ReplayResult,
		CrossCapsuleBindingResult:        baseline.CrossCapsuleBindingResult,
		EndToEndResult:                   "non-conformant",
		ChainIdentity:                    baseline.ChainIdentity,
		TrustResult:                      "not-evaluated-by-p1-a6",
		ProductionInteroperabilityResult: "not-evaluated-by-p1-a6",
		Findings:                         []Finding{},
	}
	if baseline.EndToEndResult != "conformant" || baseline.StructuralResult != "conformant" {
		result.add("P1A6.BASELINE.INVALID", "P1-A5", "independent P1-A5 baseline did not produce a conformant projection")
		return result
	}
	result.BaselineRouteResult = "conformant"
	if err := Observe(root); err != nil {
		result.ExternalObservationResult = "invalid"
		result.ExternalLibraryResult = "invalid"
		result.add("P1A6.EXTERNAL.OBSERVATION", "tests/fixtures/p1-a3/capsule.json", err.Error())
		return result
	}
	result.ExternalObservationResult = "conformant"
	result.ExternalLibraryResult = "valid"
	result.StructuralResult = "conformant"
	result.EndToEndResult = "conformant"
	return result
}

func Observe(root string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	capsuleRaw, err := os.ReadFile(filepath.Join(rootAbs, "tests/fixtures/p1-a3/capsule.json"))
	if err != nil {
		return err
	}
	bundleRaw, err := os.ReadFile(filepath.Join(rootAbs, "tests/fixtures/p1-a2/bundle.json"))
	if err != nil {
		return err
	}
	issuer, issuerDER, err := readEd25519(filepath.Join(rootAbs, "tests/fixtures/p1-a3/issuer-public-key.pem"))
	if err != nil {
		return fmt.Errorf("issuer key: %w", err)
	}
	transparency, transparencyDER, err := readEd25519(filepath.Join(rootAbs, "tests/fixtures/p1-a3/ts-public-key.pem"))
	if err != nil {
		return fmt.Errorf("transparency service key: %w", err)
	}
	value, err := strictJSON(capsuleRaw)
	if err != nil {
		return fmt.Errorf("capsule JSON: %w", err)
	}
	capsule, ok := value.(map[string]any)
	if !ok {
		return errors.New("capsule root must be an object")
	}
	if str(capsule["standard"]) != "EIGIIB-P1-A3-1.0" || str(capsule["profile"]) != "scitt-p1-a2-receipt-v1" || str(capsule["trust_scope"]) != "supplied-public-keys-only" {
		return errors.New("P1-A3 constants differ from the external observation contract")
	}
	binding := obj(capsule["binding"])
	if !identityEqual(binding["p1A2Bundle"], identity(bundleRaw)) || str(binding["vds"]) != "RFC9162_SHA256" || integer(binding["vdsId"]) != 1 || str(binding["proofType"]) != "inclusion" || integer(binding["treeSize"]) != 1 || integer(binding["leafIndex"]) != 0 {
		return errors.New("P1-A3 binding differs from the external observation contract")
	}
	signed := obj(capsule["signedStatement"])
	signedRaw, err := decodeCanonicalBase64(signed["data"])
	if err != nil {
		return fmt.Errorf("Signed Statement base64: %w", err)
	}
	if !identityEqual(signed["identity"], identity(signedRaw)) || !identityEqual(signed["issuerKeySpki"], identity(issuerDER)) {
		return errors.New("Signed Statement identity binding mismatch")
	}
	bundleSubject := "urn:eigiib:p1-a2:" + identity(bundleRaw).Digest
	if err := verifySignedStatement(signedRaw, bundleRaw, bundleSubject, issuer, issuerDER); err != nil {
		return err
	}
	receipt := obj(capsule["receipt"])
	receiptRaw, err := decodeCanonicalBase64(receipt["data"])
	if err != nil {
		return fmt.Errorf("Receipt base64: %w", err)
	}
	if !identityEqual(receipt["identity"], identity(receiptRaw)) || !identityEqual(receipt["transparencyServiceKeySpki"], identity(transparencyDER)) {
		return errors.New("Receipt identity binding mismatch")
	}
	if err := verifyReceipt(receiptRaw, signedRaw, bundleSubject, transparency, transparencyDER); err != nil {
		return err
	}
	registration := obj(capsule["registration"])
	if str(registration["apiProfile"]) != "draft-ietf-scitt-scrapi-11" || str(registration["transcriptMode"]) != "fixture-no-network" || str(registration["method"]) != "POST" || str(registration["resource"]) != "/entries" || integer(registration["status"]) != 201 || str(registration["requestMediaType"]) != signedStatementMedia || str(registration["receiptMediaType"]) != receiptMedia || str(registration["location"]) != "https://transparency.example/entries/"+identity(signedRaw).Digest {
		return errors.New("registration transcript differs from the external observation contract")
	}
	return nil
}

func verifySignedStatement(raw, bundleRaw []byte, subject string, publicKey ed25519.PublicKey, publicDER []byte) error {
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(raw); err != nil {
		return fmt.Errorf("go-cose Signed Statement parse: %w", err)
	}
	if err := requireCanonicalSign1(raw, &message); err != nil {
		return fmt.Errorf("Signed Statement encoding: %w", err)
	}
	if len(message.Headers.Unprotected) != 0 {
		return errors.New("Signed Statement unprotected header must be empty")
	}
	expectedClaims := map[any]any{int64(1): issuerID, int64(2): subject}
	if err := requireProtectedHeaders(message.Headers.Protected, map[any]any{
		int64(cose.HeaderLabelAlgorithm):   cose.AlgorithmEdDSA,
		int64(cose.HeaderLabelContentType): "application/cbor",
		int64(cose.HeaderLabelKeyID):       sha256Bytes(publicDER),
		int64(cose.HeaderLabelCWTClaims):   expectedClaims,
		int64(cose.HeaderLabelType):        signedStatementMedia,
	}); err != nil {
		return fmt.Errorf("Signed Statement protected header: %w", err)
	}
	payload, err := decodeCanonicalCBORMap(message.Payload)
	if err != nil {
		return fmt.Errorf("Signed Statement payload: %w", err)
	}
	if !reflect.DeepEqual(normalize(payload), normalize(map[any]any{
		"mediaType": bundleMedia,
		"sha256":    sha256Bytes(bundleRaw),
		"bytes":     uint64(len(bundleRaw)),
	})) {
		return errors.New("Signed Statement payload binding mismatch")
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, publicKey)
	if err != nil {
		return fmt.Errorf("go-cose Signed Statement verifier: %w", err)
	}
	if err := message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("go-cose Signed Statement signature: %w", err)
	}
	return nil
}

func verifyReceipt(raw, signedStatementRaw []byte, subject string, publicKey ed25519.PublicKey, publicDER []byte) error {
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(raw); err != nil {
		return fmt.Errorf("go-cose Receipt parse: %w", err)
	}
	if err := requireCanonicalSign1(raw, &message); err != nil {
		return fmt.Errorf("Receipt encoding: %w", err)
	}
	if message.Payload != nil {
		return errors.New("Receipt payload must be detached")
	}
	expectedClaims := map[any]any{int64(1): transparencyServiceID, int64(2): subject}
	if err := requireProtectedHeaders(message.Headers.Protected, map[any]any{
		int64(cose.HeaderLabelAlgorithm): cose.AlgorithmEdDSA,
		int64(cose.HeaderLabelKeyID):     sha256Bytes(publicDER),
		int64(cose.HeaderLabelCWTClaims): expectedClaims,
		int64(cose.HeaderLabelType):      receiptMedia,
		int64(395):                       int64(1),
	}); err != nil {
		return fmt.Errorf("Receipt protected header: %w", err)
	}
	if len(message.Headers.Unprotected) != 1 {
		return errors.New("Receipt unprotected header must contain only the verification data")
	}
	proofsValue, ok := lookupInt(message.Headers.Unprotected, 396)
	if !ok {
		return errors.New("Receipt verification data header is missing")
	}
	proofMap, ok := asMap(proofsValue)
	if !ok || len(proofMap) != 1 {
		return errors.New("Receipt verification data must contain one proof type")
	}
	proofListValue, ok := lookupInt(proofMap, -1)
	if !ok {
		return errors.New("Receipt inclusion proof list is missing")
	}
	proofList, ok := proofListValue.([]any)
	if !ok {
		if values, ok2 := proofListValue.([]interface{}); ok2 {
			proofList = values
			ok = true
		}
	}
	if !ok || len(proofList) != 1 {
		return errors.New("Receipt must contain exactly one inclusion proof")
	}
	proofRaw, ok := proofList[0].([]byte)
	if !ok {
		return errors.New("Receipt inclusion proof must be a byte string")
	}
	proof, err := decodeCanonicalCBORArray(proofRaw)
	if err != nil {
		return fmt.Errorf("Receipt inclusion proof: %w", err)
	}
	if len(proof) != 3 || integerAny(proof[0]) != 1 || integerAny(proof[1]) != 0 {
		return errors.New("Receipt inclusion coordinates differ from the bounded fixture")
	}
	path, ok := proof[2].([]any)
	if !ok {
		if values, ok2 := proof[2].([]interface{}); ok2 {
			path = values
			ok = true
		}
	}
	if !ok || len(path) != 0 {
		return errors.New("one-entry Receipt inclusion path must be empty")
	}
	root := leafHash(signedStatementRaw)
	message.Payload = root
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, publicKey)
	if err != nil {
		return fmt.Errorf("go-cose Receipt verifier: %w", err)
	}
	if err := message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("go-cose Receipt signature: %w", err)
	}
	return nil
}

func requireCanonicalSign1(raw []byte, message *cose.Sign1Message) error {
	copyMessage := *message
	copyMessage.Headers.RawProtected = nil
	copyMessage.Headers.RawUnprotected = nil
	encoded, err := copyMessage.MarshalCBOR()
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, raw) {
		return errors.New("COSE_Sign1 is not deterministic CBOR")
	}
	return nil
}

func requireProtectedHeaders(actual cose.ProtectedHeader, expected map[any]any) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("expected %d protected headers, got %d", len(expected), len(actual))
	}
	if !reflect.DeepEqual(normalize(actual), normalize(expected)) {
		return fmt.Errorf("protected headers differ from the closed profile")
	}
	return nil
}

func decodeCanonicalCBORMap(raw []byte) (map[any]any, error) {
	var value map[any]any
	if err := cbor.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	encoded, err := mode.Marshal(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, raw) {
		return nil, errors.New("CBOR map is not deterministic")
	}
	return value, nil
}

func decodeCanonicalCBORArray(raw []byte) ([]any, error) {
	var value []any
	if err := cbor.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	encoded, err := mode.Marshal(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, raw) {
		return nil, errors.New("CBOR array is not deterministic")
	}
	return value, nil
}

func readEd25519(path string) (ed25519.PublicKey, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return nil, nil, errors.New("expected one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, nil, errors.New("public key is not Ed25519")
	}
	return key, block.Bytes, nil
}

func decodeCanonicalBase64(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return nil, errors.New("base64 value must be a non-empty string")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(raw) != text {
		return nil, errors.New("base64 value is not canonical")
	}
	return raw, nil
}

func identity(raw []byte) p1verify.Identity {
	digest := sha256.Sum256(raw)
	return p1verify.Identity{Algorithm: "sha256", Digest: hex.EncodeToString(digest[:]), Bytes: len(raw)}
}

func identityEqual(value any, expected p1verify.Identity) bool {
	mapping := obj(value)
	return str(mapping["algorithm"]) == expected.Algorithm && str(mapping["digest"]) == expected.Digest && integer(mapping["bytes"]) == expected.Bytes
}

func sha256Bytes(raw []byte) []byte {
	digest := sha256.Sum256(raw)
	return digest[:]
}

func leafHash(raw []byte) []byte {
	prefixed := append([]byte{0}, raw...)
	return sha256Bytes(prefixed)
}

func normalize(value any) any {
	switch typed := value.(type) {
	case cose.Algorithm:
		return int64(typed)
	case map[any]any:
		out := map[any]any{}
		for key, item := range typed {
			out[normalizeInteger(key)] = normalize(item)
		}
		return out
	case cose.ProtectedHeader:
		out := map[any]any{}
		for key, item := range typed {
			out[normalizeInteger(key)] = normalize(item)
		}
		return out
	case cose.CWTClaims:
		out := map[any]any{}
		for key, item := range typed {
			out[normalizeInteger(key)] = normalize(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = normalize(item)
		}
		return out
	case uint:
		return int64(typed)
	case uint8:
		return int64(typed)
	case uint16:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed)
		}
		return typed
	case int:
		return int64(typed)
	case int8:
		return int64(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	default:
		return value
	}
}

func normalizeInteger(value any) any {
	switch typed := normalize(value).(type) {
	case int64:
		return typed
	default:
		return typed
	}
}

func lookupInt(mapping map[any]any, label int64) (any, bool) {
	for key, value := range mapping {
		if integerAny(key) == label {
			return value, true
		}
	}
	return nil, false
}

func asMap(value any) (map[any]any, bool) {
	switch typed := value.(type) {
	case map[any]any:
		return typed, true
	case cose.CWTClaims:
		out := map[any]any{}
		for key, item := range typed {
			out[key] = item
		}
		return out, true
	default:
		return nil, false
	}
}

func integerAny(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int8:
		return int64(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return int64(typed)
	case uint8:
		return int64(typed)
	case uint16:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed)
		}
	case json.Number:
		parsed, _ := strconv.ParseInt(typed.String(), 10, 64)
		return parsed
	}
	return -1 << 63
}

func obj(value any) map[string]any {
	mapping, _ := value.(map[string]any)
	return mapping
}

func str(value any) string {
	text, _ := value.(string)
	return text
}

func integer(value any) int {
	switch typed := value.(type) {
	case json.Number:
		parsed, _ := strconv.Atoi(typed.String())
		return parsed
	case int:
		return typed
	case int64:
		return int(typed)
	case uint64:
		return int(typed)
	}
	return -1
}

func (result *Result) add(code, path, message string) {
	result.Findings = append(result.Findings, Finding{Severity: "error", Code: code, Path: path, Message: message})
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Code != result.Findings[j].Code {
			return result.Findings[i].Code < result.Findings[j].Code
		}
		return result.Findings[i].Path < result.Findings[j].Path
	})
}
