package p1release

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
	"io"
	"strconv"
)

const Standard = "EIGIIB-P1-A9-ROUTE-1.0"
const Route = "independent-go-stdlib"
const releasePayloadType = "application/vnd.eigiib.release+json"
const supersessionPayloadType = "application/vnd.eigiib.release-supersession+json"
const statementType = "application/scitt-statement+cose"
const receiptType = "application/scitt-receipt+cose"
const relation = "authority-carrier-upgrade"

type Result struct {
	Standard                   string `json:"standard"`
	Route                      string `json:"route"`
	ReleaseID                  string `json:"release_id"`
	ReleaseDescriptorSHA256    string `json:"release_descriptor_sha256"`
	ReleaseEnvelopeSHA256      string `json:"release_envelope_sha256"`
	SupersessionEnvelopeSHA256 string `json:"supersession_envelope_sha256"`
	TransparencyRoot           string `json:"transparency_root"`
	RegisteredEntryCount       int    `json:"registered_entry_count"`
	Accepted                   bool   `json:"accepted"`
	Boundary                   string `json:"boundary"`
}

type capsuleCarrier struct {
	Standard      string `json:"standard"`
	Profile       string `json:"profile"`
	SourceRelease struct {
		Identity  identityCarrier `json:"identity"`
		Path      string          `json:"path"`
		ReleaseID string          `json:"releaseId"`
	} `json:"sourceRelease"`
	PublicKeys struct {
		ReleaseSignerSPKI       identityCarrier `json:"releaseSignerSpki"`
		TransparencyServiceSPKI identityCarrier `json:"transparencyServiceSpki"`
	} `json:"publicKeys"`
	ReleaseEnvelope dataPayloadCarrier `json:"releaseEnvelope"`
	Supersession    struct {
		Envelope dataPayloadCarrier `json:"envelope"`
		Payload  dataCarrier        `json:"payload"`
		Relation string             `json:"relation"`
	} `json:"supersession"`
	Transparency struct {
		TreeSize int             `json:"treeSize"`
		Root     identityCarrier `json:"root"`
		Entries  []entryCarrier  `json:"entries"`
	} `json:"transparency"`
	ClaimBoundary struct {
		DoesNotImply []string `json:"doesNotImply"`
	} `json:"claimBoundary"`
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
type dataPayloadCarrier struct {
	Data        string          `json:"data"`
	Identity    identityCarrier `json:"identity"`
	PayloadType string          `json:"payloadType"`
}
type entryCarrier struct {
	Kind            string      `json:"kind"`
	LeafIndex       int         `json:"leafIndex"`
	SignedStatement dataCarrier `json:"signedStatement"`
	Receipt         dataCarrier `json:"receipt"`
	Registration    struct {
		Method   string `json:"method"`
		Resource string `json:"resource"`
		Status   int    `json:"status"`
		Location string `json:"location"`
		Mode     string `json:"mode"`
	} `json:"registration"`
}

func parseValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			kt, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kt.(string)
			if !ok {
				return nil, errors.New("object key")
			}
			if _, dup := object[key]; dup {
				return nil, fmt.Errorf("duplicate JSON member: %s", key)
			}
			v, err := parseValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = v
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("object terminator")
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			v, err := parseValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, v)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("array terminator")
		}
		return array, nil
	}
	return nil, errors.New("unexpected delimiter")
}
func strictJSON(raw []byte) (map[string]any, error) {
	if !json.Valid(raw) {
		return nil, errors.New("invalid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := parseValue(d)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("root")
	}
	return o, nil
}
func decodeStruct(raw []byte, out any) error {
	if _, err := strictJSON(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	return nil
}
func canonicalBase64(s string) ([]byte, error) {
	r, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(r) != s {
		return nil, errors.New("noncanonical base64")
	}
	return r, nil
}
func sameIdentity(i identityCarrier, raw []byte) bool {
	sum := sha256.Sum256(raw)
	return i.Algorithm == "sha256" && i.Bytes == len(raw) && i.Digest == hex.EncodeToString(sum[:])
}
func readEd25519(raw []byte) (ed25519.PublicKey, []byte, error) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("pem")
	}
	v, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, ok := v.(ed25519.PublicKey)
	if !ok || len(k) != ed25519.PublicKeySize || len(b.Bytes) != 44 {
		return nil, nil, errors.New("ed25519 spki")
	}
	return k, b.Bytes, nil
}
func pae(pt string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len([]byte(pt)), pt, len(payload), payload))
}
func parseDSSE(raw []byte, pt string, expected []byte, key ed25519.PublicKey, der []byte) bool {
	var d struct {
		Standard string `json:"standard"`
		Bundle   struct {
			Envelope struct {
				Payload     string `json:"payload"`
				PayloadType string `json:"payloadType"`
				Signatures  []struct {
					KeyID string `json:"keyid"`
					Sig   string `json:"sig"`
				} `json:"signatures"`
			} `json:"dsseEnvelope"`
		} `json:"bundle"`
	}
	if decodeStruct(raw, &d) != nil || d.Standard != "EIGIIB-P1-A9-DSSE-1.0" || d.Bundle.Envelope.PayloadType != pt || len(d.Bundle.Envelope.Signatures) != 1 {
		return false
	}
	payload, err := canonicalBase64(d.Bundle.Envelope.Payload)
	if err != nil || !bytes.Equal(payload, expected) {
		return false
	}
	sig, err := canonicalBase64(d.Bundle.Envelope.Signatures[0].Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	kid := sha256.Sum256(der)
	if d.Bundle.Envelope.Signatures[0].KeyID != "p1-a9-ed25519-spki-sha256:"+hex.EncodeToString(kid[:]) {
		return false
	}
	return ed25519.Verify(key, pae(pt, payload), sig)
}
func mapExact(m map[any]any, expected map[int64]any) bool {
	if len(m) != len(expected) {
		return false
	}
	for k, v := range expected {
		got, ok := lookupInt(m, k)
		if !ok || !deepEqual(got, v) {
			return false
		}
	}
	return true
}
func deepEqual(a, b any) bool { return fmt.Sprintf("%#v", a) == fmt.Sprintf("%#v", b) }
func parseStatement(raw []byte, kind string, env, release []byte, extra any, key ed25519.PublicKey, der []byte, releaseID string) bool {
	v, err := decodeCBOR(raw)
	if err != nil {
		return false
	}
	tag, ok := v.(cborTag)
	if !ok || tag.Number != 18 {
		return false
	}
	arr, ok := tag.Value.([]any)
	if !ok || len(arr) != 4 {
		return false
	}
	pr, ok := arr[0].([]byte)
	if !ok {
		return false
	}
	unp, ok := arr[1].(map[any]any)
	if !ok || len(unp) != 0 {
		return false
	}
	payload, ok := arr[2].([]byte)
	if !ok {
		return false
	}
	sig, ok := arr[3].([]byte)
	if !ok || len(sig) != 64 {
		return false
	}
	pv, err := decodeCBOR(pr)
	if err != nil {
		return false
	}
	pm, ok := pv.(map[any]any)
	if !ok {
		return false
	}
	kid := sha256.Sum256(der)
	claims := map[any]any{int64(1): "https://eigiib.example/p1-a9/release-authority", int64(2): "urn:eigiib:p1-a9:" + kind}
	if !mapExact(pm, map[int64]any{1: int64(-8), 3: "application/cbor", 4: kid[:], 15: claims, 16: statementType}) {
		return false
	}
	bodyv, err := decodeCBOR(payload)
	if err != nil {
		return false
	}
	body, ok := bodyv.(map[any]any)
	if !ok {
		return false
	}
	envsum := sha256.Sum256(env)
	relsum := sha256.Sum256(release)
	if !mapExact(body, map[int64]any{1: kind, 2: envsum[:], 3: int64(len(env)), 4: relsum[:], 5: releaseID, 6: extra}) {
		return false
	}
	ss, err := encodeCBOR([]any{"Signature1", pr, []byte{}, payload})
	return err == nil && ed25519.Verify(key, ss, sig)
}
func leaf(raw []byte) []byte { s := sha256.Sum256(append([]byte{0}, raw...)); return s[:] }
func node(l, r []byte) []byte {
	b := make([]byte, 1+len(l)+len(r))
	b[0] = 1
	copy(b[1:], l)
	copy(b[1+len(l):], r)
	s := sha256.Sum256(b)
	return s[:]
}
func parseReceipt(raw []byte, kind string, stmt []byte, index int, sibling, root []byte, key ed25519.PublicKey, der []byte) bool {
	v, err := decodeCBOR(raw)
	if err != nil {
		return false
	}
	tag, ok := v.(cborTag)
	if !ok || tag.Number != 18 {
		return false
	}
	arr, ok := tag.Value.([]any)
	if !ok || len(arr) != 4 {
		return false
	}
	pr, ok := arr[0].([]byte)
	if !ok {
		return false
	}
	unp, ok := arr[1].(map[any]any)
	if !ok || arr[2] != nil {
		return false
	}
	sig, ok := arr[3].([]byte)
	if !ok || len(sig) != 64 {
		return false
	}
	pv, err := decodeCBOR(pr)
	if err != nil {
		return false
	}
	pm, ok := pv.(map[any]any)
	if !ok {
		return false
	}
	kid := sha256.Sum256(der)
	claims := map[any]any{int64(1): "https://eigiib.example/p1-a9/transparency-service", int64(2): "urn:eigiib:p1-a9:" + kind + ":" + hex.EncodeToString(sha256Bytes(stmt))}
	if !mapExact(pm, map[int64]any{1: int64(-8), 4: kid[:], 15: claims, 16: receiptType, 395: int64(1)}) {
		return false
	}
	pc, ok := lookupInt(unp, 396)
	if !ok {
		return false
	}
	pcm, ok := pc.(map[any]any)
	if !ok {
		return false
	}
	ps, ok := lookupInt(pcm, -1)
	if !ok {
		return false
	}
	pa, ok := ps.([]any)
	if !ok || len(pa) != 1 {
		return false
	}
	proofRaw, ok := pa[0].([]byte)
	if !ok {
		return false
	}
	pval, err := decodeCBOR(proofRaw)
	if err != nil {
		return false
	}
	proof, ok := pval.([]any)
	if !ok || len(proof) != 3 {
		return false
	}
	tree, _ := integer(proof[0])
	leafIndex, _ := integer(proof[1])
	path, ok := proof[2].([]any)
	if tree != 2 || leafIndex != int64(index) || !ok || len(path) != 1 || !bytes.Equal(asBytes(path[0]), sibling) {
		return false
	}
	calc := node(leaf(stmt), sibling)
	if index == 1 {
		calc = node(sibling, leaf(stmt))
	}
	if !bytes.Equal(calc, root) {
		return false
	}
	ss, err := encodeCBOR([]any{"Signature1", pr, []byte{}, root})
	return err == nil && ed25519.Verify(key, ss, sig)
}
func sha256Bytes(raw []byte) []byte { s := sha256.Sum256(raw); return s[:] }
func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := strconv.ParseInt(n.String(), 10, 64)
	return i, e == nil
}

func Evaluate(capsuleRaw, releaseRaw, releasePEM, tsPEM []byte) Result {
	reject := func() Result {
		return Result{Standard: Standard, Route: Route, Accepted: false, Boundary: "p1-a9-replay"}
	}
	var c capsuleCarrier
	if decodeStruct(capsuleRaw, &c) != nil || c.Standard != "EIGIIB-P1-A9-1.0" || c.Profile != "authenticated-release-registration-supersession-v1" {
		return reject()
	}
	releaseKey, releaseDER, err := readEd25519(releasePEM)
	if err != nil {
		return reject()
	}
	tsKey, tsDER, err := readEd25519(tsPEM)
	if err != nil {
		return reject()
	}
	if !sameIdentity(c.SourceRelease.Identity, releaseRaw) || !sameIdentity(c.PublicKeys.ReleaseSignerSPKI, releaseDER) || !sameIdentity(c.PublicKeys.TransparencyServiceSPKI, tsDER) {
		return reject()
	}
	var releaseDoc map[string]any
	if decodeStruct(releaseRaw, &releaseDoc) != nil {
		return reject()
	}
	releaseID, _ := releaseDoc["releaseId"].(string)
	authorityRoot, _ := releaseDoc["authorityRoot"].(string)
	if releaseID == "" || releaseID != c.SourceRelease.ReleaseID {
		return reject()
	}
	releaseEnv, err := canonicalBase64(c.ReleaseEnvelope.Data)
	if err != nil || !sameIdentity(c.ReleaseEnvelope.Identity, releaseEnv) || c.ReleaseEnvelope.PayloadType != releasePayloadType || !parseDSSE(releaseEnv, releasePayloadType, releaseRaw, releaseKey, releaseDER) {
		return reject()
	}
	supPayload, err := canonicalBase64(c.Supersession.Payload.Data)
	if err != nil || !sameIdentity(c.Supersession.Payload.Identity, supPayload) {
		return reject()
	}
	supEnv, err := canonicalBase64(c.Supersession.Envelope.Data)
	if err != nil || !sameIdentity(c.Supersession.Envelope.Identity, supEnv) || c.Supersession.Envelope.PayloadType != supersessionPayloadType || c.Supersession.Relation != relation || !parseDSSE(supEnv, supersessionPayloadType, supPayload, releaseKey, releaseDER) {
		return reject()
	}
	var supDoc map[string]any
	if decodeStruct(supPayload, &supDoc) != nil {
		return reject()
	}
	pred, _ := supDoc["predecessor"].(map[string]any)
	succ, _ := supDoc["successor"].(map[string]any)
	pres, _ := supDoc["preserves"].(map[string]any)
	pseq, pok := asInt(pred["sequence"])
	sseq, sok := asInt(succ["sequence"])
	if supDoc["relation"] != relation || pseq != 0 || sseq != 1 || !pok || !sok || pred["releaseId"] != releaseID || succ["releaseId"] != releaseID || pred["authorityType"] != "detached-release-digest" || succ["authorityType"] != "authenticated-release-envelope" {
		return reject()
	}
	reldocID, ok := pred["releaseDescriptor"].(map[string]any)
	if !ok {
		return reject()
	}
	presID, ok := pres["releaseDescriptor"].(map[string]any)
	if !ok {
		return reject()
	}
	envID, ok := succ["releaseEnvelope"].(map[string]any)
	if !ok {
		return reject()
	}
	if !identityMapMatches(reldocID, releaseRaw) || !identityMapMatches(presID, releaseRaw) || !identityMapMatches(envID, releaseEnv) {
		return reject()
	}
	if c.Transparency.TreeSize != 2 || len(c.Transparency.Entries) != 2 || c.Transparency.Entries[0].Kind != "release-envelope" || c.Transparency.Entries[0].LeafIndex != 0 || c.Transparency.Entries[1].Kind != "supersession-envelope" || c.Transparency.Entries[1].LeafIndex != 1 {
		return reject()
	}
	stmts := make([][]byte, 2)
	receipts := make([][]byte, 2)
	for i := 0; i < 2; i++ {
		stmts[i], err = canonicalBase64(c.Transparency.Entries[i].SignedStatement.Data)
		if err != nil || !sameIdentity(c.Transparency.Entries[i].SignedStatement.Identity, stmts[i]) {
			return reject()
		}
		receipts[i], err = canonicalBase64(c.Transparency.Entries[i].Receipt.Data)
		if err != nil || !sameIdentity(c.Transparency.Entries[i].Receipt.Identity, receipts[i]) {
			return reject()
		}
		reg := c.Transparency.Entries[i].Registration
		if reg.Method != "POST" || reg.Resource != "/entries" || reg.Status != 201 || reg.Mode != "fixture-no-network" || reg.Location != "https://transparency.example/entries/"+hex.EncodeToString(sha256Bytes(stmts[i])) {
			return reject()
		}
	}
	if !parseStatement(stmts[0], "release-envelope", releaseEnv, releaseRaw, authorityRoot, releaseKey, releaseDER, releaseID) || !parseStatement(stmts[1], "supersession-envelope", supEnv, releaseRaw, relation, releaseKey, releaseDER, releaseID) {
		return reject()
	}
	root := node(leaf(stmts[0]), leaf(stmts[1]))
	if c.Transparency.Root.Algorithm != "rfc9162-sha256" || c.Transparency.Root.Bytes != 32 || c.Transparency.Root.Digest != hex.EncodeToString(root) {
		return reject()
	}
	if !parseReceipt(receipts[0], "release-envelope", stmts[0], 0, leaf(stmts[1]), root, tsKey, tsDER) || !parseReceipt(receipts[1], "supersession-envelope", stmts[1], 1, leaf(stmts[0]), root, tsKey, tsDER) {
		return reject()
	}
	rs := sha256.Sum256(releaseRaw)
	re := sha256.Sum256(releaseEnv)
	se := sha256.Sum256(supEnv)
	return Result{Standard: Standard, Route: Route, ReleaseID: releaseID, ReleaseDescriptorSHA256: hex.EncodeToString(rs[:]), ReleaseEnvelopeSHA256: hex.EncodeToString(re[:]), SupersessionEnvelopeSHA256: hex.EncodeToString(se[:]), TransparencyRoot: hex.EncodeToString(root), RegisteredEntryCount: 2, Accepted: true, Boundary: "supersession-current-authority"}
}
func identityMapMatches(m map[string]any, raw []byte) bool {
	alg, _ := m["algorithm"].(string)
	dig, _ := m["digest"].(string)
	n, ok := asInt(m["bytes"])
	sum := sha256.Sum256(raw)
	return ok && alg == "sha256" && dig == hex.EncodeToString(sum[:]) && n == int64(len(raw))
}
