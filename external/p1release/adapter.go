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
	"reflect"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const Standard = "EIGIIB-P1-A9-ROUTE-1.0"
const Route = "external-go-cose"
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

func parseValue(d *json.Decoder) (any, error) {
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	del, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch del {
	case '{':
		o := map[string]any{}
		for d.More() {
			kt, e := d.Token()
			if e != nil {
				return nil, e
			}
			k, ok := kt.(string)
			if !ok {
				return nil, errors.New("key")
			}
			if _, dup := o[k]; dup {
				return nil, errors.New("duplicate JSON member")
			}
			v, e := parseValue(d)
			if e != nil {
				return nil, e
			}
			o[k] = v
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("object")
		}
		return o, nil
	case '[':
		a := []any{}
		for d.More() {
			v, e := parseValue(d)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, errors.New("array")
		}
		return a, nil
	}
	return nil, errors.New("delimiter")
}
func strictJSON(raw []byte) (map[string]any, error) {
	if !json.Valid(raw) {
		return nil, errors.New("json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := parseValue(d)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing")
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("root")
	}
	return o, nil
}
func decodeStruct(raw []byte, out any) error {
	if _, e := strictJSON(raw); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func canonicalBase64(s string) ([]byte, error) {
	r, e := base64.StdEncoding.DecodeString(s)
	if e != nil || base64.StdEncoding.EncodeToString(r) != s {
		return nil, errors.New("base64")
	}
	return r, nil
}
func sameIdentity(i identityCarrier, raw []byte) bool {
	s := sha256.Sum256(raw)
	return i.Algorithm == "sha256" && i.Bytes == len(raw) && i.Digest == hex.EncodeToString(s[:])
}
func readEd25519(raw []byte) (ed25519.PublicKey, []byte, error) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("pem")
	}
	v, e := x509.ParsePKIXPublicKey(b.Bytes)
	if e != nil {
		return nil, nil, e
	}
	k, ok := v.(ed25519.PublicKey)
	if !ok || len(k) != 32 || len(b.Bytes) != 44 {
		return nil, nil, errors.New("ed25519")
	}
	return k, b.Bytes, nil
}
func pae(pt string, p []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len([]byte(pt)), pt, len(p), p))
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
	p, e := canonicalBase64(d.Bundle.Envelope.Payload)
	if e != nil || !bytes.Equal(p, expected) {
		return false
	}
	sig, e := canonicalBase64(d.Bundle.Envelope.Signatures[0].Sig)
	if e != nil {
		return false
	}
	kid := sha256.Sum256(der)
	return d.Bundle.Envelope.Signatures[0].KeyID == "p1-a9-ed25519-spki-sha256:"+hex.EncodeToString(kid[:]) && ed25519.Verify(key, pae(pt, p), sig)
}
func asMap(v any) (map[any]any, bool) { m, ok := v.(map[any]any); return m, ok }
func integer(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case uint64:
		if x <= uint64(^uint64(0)>>1) {
			return int64(x), true
		}
	case int:
		return int64(x), true
	case uint:
		return int64(x), true
	}
	return 0, false
}
func lookup(m map[any]any, k int64) (any, bool) {
	if v, ok := m[k]; ok {
		return v, true
	}
	if k >= 0 {
		v, ok := m[uint64(k)]
		return v, ok
	}
	return nil, false
}
func equivalent(a, b any) bool {
	if ai, ok := integer(a); ok {
		if bi, ok := integer(b); ok {
			return ai == bi
		}
	}
	if ab, ok := a.([]byte); ok {
		bb, ok := b.([]byte)
		return ok && bytes.Equal(ab, bb)
	}
	if am, ok := asMap(a); ok {
		bm, ok := asMap(b)
		if !ok || len(am) != len(bm) {
			return false
		}
		for key, av := range am {
			var bv any
			var found bool
			if ki, ok := integer(key); ok {
				bv, found = lookup(bm, ki)
			} else {
				bv, found = bm[key]
			}
			if !found || !equivalent(av, bv) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}
func mapExact(m map[any]any, exp map[int64]any) bool {
	if len(m) != len(exp) {
		return false
	}
	for k, v := range exp {
		g, ok := lookup(m, k)
		if !ok || !equivalent(g, v) {
			return false
		}
	}
	return true
}
func canonicalCBOR(raw []byte) (any, cbor.EncMode, bool) {
	mode, e := cbor.CanonicalEncOptions().EncMode()
	if e != nil {
		return nil, nil, false
	}
	var v any
	if cbor.Unmarshal(raw, &v) != nil {
		return nil, nil, false
	}
	out, e := mode.Marshal(v)
	return v, mode, e == nil && bytes.Equal(out, raw)
}
func parseStatement(raw []byte, kind string, env, release []byte, extra any, key ed25519.PublicKey, der []byte, releaseID string) bool {
	v, mode, ok := canonicalCBOR(raw)
	if !ok {
		return false
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != 18 {
		return false
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return false
	}
	pr, ok := arr[0].([]byte)
	if !ok {
		return false
	}
	unp, ok := asMap(arr[1])
	if !ok || len(unp) != 0 {
		return false
	}
	payload, ok := arr[2].([]byte)
	if !ok {
		return false
	}
	pv, _, ok := canonicalCBOR(pr)
	if !ok {
		return false
	}
	pm, ok := asMap(pv)
	if !ok {
		return false
	}
	kid := sha256.Sum256(der)
	claims := map[any]any{int64(1): "https://eigiib.example/p1-a9/release-authority", int64(2): "urn:eigiib:p1-a9:" + kind}
	if !mapExact(pm, map[int64]any{1: int64(-8), 3: "application/cbor", 4: kid[:], 15: claims, 16: statementType}) {
		return false
	}
	bodyv, _, ok := canonicalCBOR(payload)
	if !ok {
		return false
	}
	body, ok := asMap(bodyv)
	if !ok {
		return false
	}
	es := sha256.Sum256(env)
	rs := sha256.Sum256(release)
	if !mapExact(body, map[int64]any{1: kind, 2: es[:], 3: uint64(len(env)), 4: rs[:], 5: releaseID, 6: extra}) && !mapExact(body, map[int64]any{1: kind, 2: es[:], 3: int64(len(env)), 4: rs[:], 5: releaseID, 6: extra}) {
		return false
	}
	var msg cose.Sign1Message
	if msg.UnmarshalCBOR(raw) != nil {
		return false
	}
	ver, e := cose.NewVerifier(cose.AlgorithmEdDSA, key)
	if e != nil {
		return false
	}
	_ = mode
	return msg.Verify(nil, ver) == nil
}
func leaf(raw []byte) []byte { s := sha256.Sum256(append([]byte{0}, raw...)); return s[:] }
func node(l, r []byte) []byte {
	b := append([]byte{1}, append(append([]byte{}, l...), r...)...)
	s := sha256.Sum256(b)
	return s[:]
}
func parseReceipt(raw []byte, kind string, stmt []byte, index int, sibling, root []byte, key ed25519.PublicKey, der []byte) bool {
	v, _, ok := canonicalCBOR(raw)
	if !ok {
		return false
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != 18 {
		return false
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return false
	}
	pr, ok := arr[0].([]byte)
	if !ok {
		return false
	}
	unp, ok := asMap(arr[1])
	if !ok || arr[2] != nil {
		return false
	}
	pv, _, ok := canonicalCBOR(pr)
	if !ok {
		return false
	}
	pm, ok := asMap(pv)
	if !ok {
		return false
	}
	kid := sha256.Sum256(der)
	ss := sha256.Sum256(stmt)
	claims := map[any]any{int64(1): "https://eigiib.example/p1-a9/transparency-service", int64(2): "urn:eigiib:p1-a9:" + kind + ":" + hex.EncodeToString(ss[:])}
	if !mapExact(pm, map[int64]any{1: int64(-8), 4: kid[:], 15: claims, 16: receiptType, 395: uint64(1)}) && !mapExact(pm, map[int64]any{1: int64(-8), 4: kid[:], 15: claims, 16: receiptType, 395: int64(1)}) {
		return false
	}
	pc, ok := lookup(unp, 396)
	if !ok {
		return false
	}
	pcm, ok := asMap(pc)
	if !ok {
		return false
	}
	ps, ok := lookup(pcm, -1)
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
	proofv, _, ok := canonicalCBOR(proofRaw)
	if !ok {
		return false
	}
	proof, ok := proofv.([]any)
	if !ok || len(proof) != 3 {
		return false
	}
	tree, _ := integer(proof[0])
	li, _ := integer(proof[1])
	path, ok := proof[2].([]any)
	if tree != 2 || li != int64(index) || !ok || len(path) != 1 || !bytes.Equal(path[0].([]byte), sibling) {
		return false
	}
	calc := node(leaf(stmt), sibling)
	if index == 1 {
		calc = node(sibling, leaf(stmt))
	}
	if !bytes.Equal(calc, root) {
		return false
	}
	var msg cose.Sign1Message
	if msg.UnmarshalCBOR(raw) != nil {
		return false
	}
	msg.Payload = root
	ver, e := cose.NewVerifier(cose.AlgorithmEdDSA, key)
	return e == nil && msg.Verify(nil, ver) == nil
}
func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := strconv.ParseInt(n.String(), 10, 64)
	return i, e == nil
}
func identityMapMatches(m map[string]any, raw []byte) bool {
	alg, _ := m["algorithm"].(string)
	dig, _ := m["digest"].(string)
	n, ok := asInt(m["bytes"])
	s := sha256.Sum256(raw)
	return ok && alg == "sha256" && dig == hex.EncodeToString(s[:]) && n == int64(len(raw))
}

func Evaluate(capsuleRaw, releaseRaw, releasePEM, tsPEM []byte) Result {
	reject := func() Result {
		return Result{Standard: Standard, Route: Route, Accepted: false, Boundary: "p1-a9-replay"}
	}
	var c capsuleCarrier
	if decodeStruct(capsuleRaw, &c) != nil || c.Standard != "EIGIIB-P1-A9-1.0" || c.Profile != "authenticated-release-registration-supersession-v1" {
		return reject()
	}
	rk, rder, e := readEd25519(releasePEM)
	if e != nil {
		return reject()
	}
	tk, tder, e := readEd25519(tsPEM)
	if e != nil {
		return reject()
	}
	if !sameIdentity(c.SourceRelease.Identity, releaseRaw) || !sameIdentity(c.PublicKeys.ReleaseSignerSPKI, rder) || !sameIdentity(c.PublicKeys.TransparencyServiceSPKI, tder) {
		return reject()
	}
	var rd map[string]any
	if decodeStruct(releaseRaw, &rd) != nil {
		return reject()
	}
	rid, _ := rd["releaseId"].(string)
	ar, _ := rd["authorityRoot"].(string)
	if rid == "" || rid != c.SourceRelease.ReleaseID {
		return reject()
	}
	renv, e := canonicalBase64(c.ReleaseEnvelope.Data)
	if e != nil || !sameIdentity(c.ReleaseEnvelope.Identity, renv) || c.ReleaseEnvelope.PayloadType != releasePayloadType || !parseDSSE(renv, releasePayloadType, releaseRaw, rk, rder) {
		return reject()
	}
	sp, e := canonicalBase64(c.Supersession.Payload.Data)
	if e != nil || !sameIdentity(c.Supersession.Payload.Identity, sp) {
		return reject()
	}
	senv, e := canonicalBase64(c.Supersession.Envelope.Data)
	if e != nil || !sameIdentity(c.Supersession.Envelope.Identity, senv) || c.Supersession.Envelope.PayloadType != supersessionPayloadType || c.Supersession.Relation != relation || !parseDSSE(senv, supersessionPayloadType, sp, rk, rder) {
		return reject()
	}
	var sd map[string]any
	if decodeStruct(sp, &sd) != nil {
		return reject()
	}
	pred, _ := sd["predecessor"].(map[string]any)
	succ, _ := sd["successor"].(map[string]any)
	pres, _ := sd["preserves"].(map[string]any)
	pseq, pok := asInt(pred["sequence"])
	sseq, sok := asInt(succ["sequence"])
	if sd["relation"] != relation || !pok || !sok || pseq != 0 || sseq != 1 || pred["releaseId"] != rid || succ["releaseId"] != rid || pred["authorityType"] != "detached-release-digest" || succ["authorityType"] != "authenticated-release-envelope" {
		return reject()
	}
	a, _ := pred["releaseDescriptor"].(map[string]any)
	b, _ := pres["releaseDescriptor"].(map[string]any)
	d, _ := succ["releaseEnvelope"].(map[string]any)
	if !identityMapMatches(a, releaseRaw) || !identityMapMatches(b, releaseRaw) || !identityMapMatches(d, renv) {
		return reject()
	}
	if c.Transparency.TreeSize != 2 || len(c.Transparency.Entries) != 2 {
		return reject()
	}
	stmts := make([][]byte, 2)
	receipts := make([][]byte, 2)
	for i := 0; i < 2; i++ {
		stmts[i], e = canonicalBase64(c.Transparency.Entries[i].SignedStatement.Data)
		if e != nil || !sameIdentity(c.Transparency.Entries[i].SignedStatement.Identity, stmts[i]) {
			return reject()
		}
		receipts[i], e = canonicalBase64(c.Transparency.Entries[i].Receipt.Data)
		if e != nil || !sameIdentity(c.Transparency.Entries[i].Receipt.Identity, receipts[i]) {
			return reject()
		}
		reg := c.Transparency.Entries[i].Registration
		ss := sha256.Sum256(stmts[i])
		if reg.Method != "POST" || reg.Resource != "/entries" || reg.Status != 201 || reg.Mode != "fixture-no-network" || reg.Location != "https://transparency.example/entries/"+hex.EncodeToString(ss[:]) {
			return reject()
		}
	}
	if !parseStatement(stmts[0], "release-envelope", renv, releaseRaw, ar, rk, rder, rid) || !parseStatement(stmts[1], "supersession-envelope", senv, releaseRaw, relation, rk, rder, rid) {
		return reject()
	}
	root := node(leaf(stmts[0]), leaf(stmts[1]))
	if c.Transparency.Root.Algorithm != "rfc9162-sha256" || c.Transparency.Root.Bytes != 32 || c.Transparency.Root.Digest != hex.EncodeToString(root) {
		return reject()
	}
	if !parseReceipt(receipts[0], "release-envelope", stmts[0], 0, leaf(stmts[1]), root, tk, tder) || !parseReceipt(receipts[1], "supersession-envelope", stmts[1], 1, leaf(stmts[0]), root, tk, tder) {
		return reject()
	}
	rs := sha256.Sum256(releaseRaw)
	re := sha256.Sum256(renv)
	se := sha256.Sum256(senv)
	return Result{Standard: Standard, Route: Route, ReleaseID: rid, ReleaseDescriptorSHA256: hex.EncodeToString(rs[:]), ReleaseEnvelopeSHA256: hex.EncodeToString(re[:]), SupersessionEnvelopeSHA256: hex.EncodeToString(se[:]), TransparencyRoot: hex.EncodeToString(root), RegisteredEntryCount: 2, Accepted: true, Boundary: "supersession-current-authority"}
}
