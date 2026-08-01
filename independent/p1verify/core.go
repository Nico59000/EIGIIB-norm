package p1verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

const (
	Standard    = "EIGIIB-P1-A5-1.0"
	ToolVersion = "0.1.0"
	chainDigest = "8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d"
	chainBytes  = 2182
)

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}
type Identity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Bytes     int    `json:"bytes"`
}
type Result struct {
	Tool                             string    `json:"tool"`
	ToolVersion                      string    `json:"tool_version"`
	Standard                         string    `json:"standard"`
	Implementation                   string    `json:"implementation"`
	StructuralResult                 string    `json:"structural_result"`
	ManifestBindingResult            string    `json:"manifest_binding_result"`
	P1A1ReplayResult                 string    `json:"p1a1_replay_result"`
	P1A2ReplayResult                 string    `json:"p1a2_replay_result"`
	P1A3ReplayResult                 string    `json:"p1a3_replay_result"`
	CrossCapsuleBindingResult        string    `json:"cross_capsule_binding_result"`
	EndToEndResult                   string    `json:"end_to_end_result"`
	ChainIdentity                    Identity  `json:"chain_identity"`
	TrustResult                      string    `json:"trust_result"`
	ProductionInteroperabilityResult string    `json:"production_interoperability_result"`
	Findings                         []Finding `json:"findings"`
}

func Verify(root string) Result {
	r := Result{Tool: "eigiib-independent-verifier", ToolVersion: ToolVersion, Standard: Standard, Implementation: "go-stdlib-ed25519-cbor-v1", StructuralResult: "non-conformant", ManifestBindingResult: "not-evaluated", P1A1ReplayResult: "not-evaluated", P1A2ReplayResult: "not-evaluated", P1A3ReplayResult: "not-evaluated", CrossCapsuleBindingResult: "not-evaluated", EndToEndResult: "non-conformant", ChainIdentity: Identity{Algorithm: "sha256", Digest: chainDigest, Bytes: chainBytes}, TrustResult: "not-evaluated-by-p1-a5", ProductionInteroperabilityResult: "not-evaluated-by-p1-a5", Findings: []Finding{}}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		r.add("P1A5.ROOT", "", err.Error())
		return r
	}
	manifestRaw, err := os.ReadFile(filepath.Join(rootAbs, "tests/fixtures/p1-a4/chain.json"))
	if err != nil {
		r.add("P1A5.MANIFEST.MISSING", "tests/fixtures/p1-a4/chain.json", err.Error())
		return r
	}
	mv, err := strictJSON(manifestRaw)
	if err != nil {
		r.add("P1A5.MANIFEST.PARSE", "tests/fixtures/p1-a4/chain.json", err.Error())
		return r
	}
	manifest, ok := mv.(map[string]any)
	if !ok {
		r.add("P1A5.MANIFEST.TYPE", "tests/fixtures/p1-a4/chain.json", "manifest root must be object")
		return r
	}
	if err = verifyManifest(rootAbs, manifest); err != nil {
		r.add("P1A5.MANIFEST.INVALID", "tests/fixtures/p1-a4/chain.json", err.Error())
		return r
	}
	r.ManifestBindingResult = "conformant"

	aggregateRaw, err := os.ReadFile(filepath.Join(rootAbs, "tests/fixtures/p1-a1/aggregate.json"))
	if err != nil {
		r.add("P1A5.P1A1.SOURCE", "tests/fixtures/p1-a1/aggregate.json", err.Error())
		return r
	}
	p1a1Raw, err := os.ReadFile(filepath.Join(rootAbs, "tests/fixtures/p1-a1/capsule.json"))
	if err != nil {
		r.add("P1A5.P1A1.CAPSULE", "tests/fixtures/p1-a1/capsule.json", err.Error())
		return r
	}
	statement, statementRaw, err := verifyP1A1(aggregateRaw, p1a1Raw)
	if err != nil {
		r.add("P1A5.P1A1.INVALID", "tests/fixtures/p1-a1/capsule.json", err.Error())
		return r
	}
	_ = statement
	r.P1A1ReplayResult = "conformant"

	bundleRaw, err := os.ReadFile(filepath.Join(rootAbs, "tests/fixtures/p1-a2/bundle.json"))
	if err != nil {
		r.add("P1A5.P1A2.CAPSULE", "tests/fixtures/p1-a2/bundle.json", err.Error())
		return r
	}
	p1a2Key, der2, err := readEd25519(filepath.Join(rootAbs, "tests/fixtures/p1-a2/public-key.pem"))
	if err != nil {
		r.add("P1A5.P1A2.KEY", "tests/fixtures/p1-a2/public-key.pem", err.Error())
		return r
	}
	if err = verifyP1A2(bundleRaw, statementRaw, p1a2Key, der2); err != nil {
		r.add("P1A5.P1A2.INVALID", "tests/fixtures/p1-a2/bundle.json", err.Error())
		return r
	}
	r.P1A2ReplayResult = "conformant"

	p1a3Raw, err := os.ReadFile(filepath.Join(rootAbs, "tests/fixtures/p1-a3/capsule.json"))
	if err != nil {
		r.add("P1A5.P1A3.CAPSULE", "tests/fixtures/p1-a3/capsule.json", err.Error())
		return r
	}
	issuer, issuerDER, err := readEd25519(filepath.Join(rootAbs, "tests/fixtures/p1-a3/issuer-public-key.pem"))
	if err != nil {
		r.add("P1A5.P1A3.ISSUER_KEY", "tests/fixtures/p1-a3/issuer-public-key.pem", err.Error())
		return r
	}
	ts, tsDER, err := readEd25519(filepath.Join(rootAbs, "tests/fixtures/p1-a3/ts-public-key.pem"))
	if err != nil {
		r.add("P1A5.P1A3.TS_KEY", "tests/fixtures/p1-a3/ts-public-key.pem", err.Error())
		return r
	}
	if err = verifyP1A3(p1a3Raw, bundleRaw, issuer, issuerDER, ts, tsDER); err != nil {
		r.add("P1A5.P1A3.INVALID", "tests/fixtures/p1-a3/capsule.json", err.Error())
		return r
	}
	r.P1A3ReplayResult = "conformant"
	r.CrossCapsuleBindingResult = "conformant"
	r.StructuralResult = "conformant"
	r.EndToEndResult = "conformant"
	return r
}

func (r *Result) add(code, path, msg string) {
	r.Findings = append(r.Findings, Finding{"error", code, path, msg})
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].Code != r.Findings[j].Code {
			return r.Findings[i].Code < r.Findings[j].Code
		}
		return r.Findings[i].Path < r.Findings[j].Path
	})
}
func ident(b []byte) Identity {
	h := sha256.Sum256(b)
	return Identity{"sha256", hex.EncodeToString(h[:]), len(b)}
}
func eqID(v any, w Identity) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return str(m["algorithm"]) == w.Algorithm && str(m["digest"]) == w.Digest && integer(m["bytes"]) == w.Bytes
}
func str(v any) string { s, _ := v.(string); return s }
func integer(v any) int {
	switch x := v.(type) {
	case json.Number:
		i, _ := strconv.Atoi(x.String())
		return i
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	}
	return -1
}
func arr(v any) []any          { a, _ := v.([]any); return a }
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
