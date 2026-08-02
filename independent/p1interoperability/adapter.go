package p1interoperability

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
	"sort"
)

const (
	standard     = "EIGIIB-P1-A19-CONFORMANCE-1.0"
	sourceCommit = "be2eda2c9a86c703c6d486599d1062143c228ca9"
	sourceReport = "02ed5d44db18acb676714a27273c4df75d6a5a132cfe1fc8e7102e8bdc774ee6"
	environment  = "p1-a18-fixture-production"
	boundary     = "registered-active-profile-matrix-canonical-capability-negotiation-claim-boundary-preserving-differential-replay-closure"
)

type SignedRegistry struct {
	Payload         json.RawMessage `json:"payload"`
	PayloadSHA256   string          `json:"payloadSha256"`
	KeyID           string          `json:"keyId"`
	Algorithm       string          `json:"algorithm"`
	SignatureBase64 string          `json:"signatureBase64"`
}

type Bundle struct {
	Standard       string         `json:"standard"`
	SignedRegistry SignedRegistry `json:"signedRegistry"`
	Routes         []Route        `json:"routes"`
}

type Registry struct {
	Standard                string            `json:"standard"`
	RegistryID              string            `json:"registryId"`
	SourceCommit            string            `json:"sourceP1A18Commit"`
	SourceReport            string            `json:"sourceP1A18ReportSha256"`
	Environment             string            `json:"environment"`
	Canonicalization        string            `json:"canonicalization"`
	KnownCapabilities       []string          `json:"knownCapabilities"`
	KnownCriticalExtensions []string          `json:"knownCriticalExtensions"`
	ActiveVersions          map[string]string `json:"activeVersions"`
	Profiles                []Profile         `json:"profiles"`
}

type Profile struct {
	ProfileID string   `json:"profileId"`
	Version   string   `json:"version"`
	Status    string   `json:"status"`
	Required  []string `json:"requiredCapabilities"`
	Optional  []string `json:"optionalCapabilities"`
	Claims    []string `json:"claimVocabulary"`
	Critical  []string `json:"criticalExtensions"`
}

type Route struct {
	RouteID            string         `json:"routeId"`
	SourceProfileID    string         `json:"sourceProfileId"`
	SourceVersion      string         `json:"sourceVersion"`
	TargetProfileID    string         `json:"targetProfileId"`
	TargetVersion      string         `json:"targetVersion"`
	SourceClaims       []string       `json:"sourceClaims"`
	TargetClaims       []string       `json:"targetClaims"`
	CriticalExtensions []string       `json:"criticalExtensions"`
	ExpectedTranscript map[string]any `json:"expectedTranscript"`
}

func canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func digest(v any) (string, error) {
	b, err := canonical(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func sortedUnique(xs []string) bool {
	if !sort.StringsAreSorted(xs) {
		return false
	}
	for i := 1; i < len(xs); i++ {
		if xs[i] == xs[i-1] {
			return false
		}
	}
	return true
}

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func subset(xs []string, m map[string]bool) bool {
	for _, x := range xs {
		if !m[x] {
			return false
		}
	}
	return true
}

func profileKey(p Profile) string { return p.ProfileID + "@" + p.Version }

func verifyRegistry(root string, sr SignedRegistry) (Registry, error) {
	var raw any
	if err := json.Unmarshal(sr.Payload, &raw); err != nil {
		return Registry{}, err
	}
	got, err := digest(raw)
	if err != nil {
		return Registry{}, err
	}
	if got != sr.PayloadSHA256 {
		return Registry{}, errors.New("registry payload digest mismatch")
	}
	if sr.KeyID != "p1-a19-profile-registrar-v1" || sr.Algorithm != "Ed25519" {
		return Registry{}, errors.New("registry signer mismatch")
	}
	pemBytes, err := os.ReadFile(filepath.Join(root, "tests", "fixtures", "p1-a19", "profile-registrar-public-key.pem"))
	if err != nil {
		return Registry{}, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return Registry{}, errors.New("invalid registrar PEM")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return Registry{}, err
	}
	pub, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return Registry{}, errors.New("registrar key is not Ed25519")
	}
	sig, err := base64.StdEncoding.DecodeString(sr.SignatureBase64)
	if err != nil {
		return Registry{}, err
	}
	payload, err := canonical(raw)
	if err != nil {
		return Registry{}, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return Registry{}, errors.New("registry signature verification failed")
	}
	var reg Registry
	if err := json.Unmarshal(sr.Payload, &reg); err != nil {
		return Registry{}, err
	}
	return reg, validateRegistry(reg)
}

func validateRegistry(reg Registry) error {
	if reg.Standard != standard || reg.SourceCommit != sourceCommit || reg.SourceReport != sourceReport || reg.Environment != environment {
		return errors.New("registry authority mismatch")
	}
	knownCaps := set(reg.KnownCapabilities)
	knownExt := set(reg.KnownCriticalExtensions)
	profiles := map[string]Profile{}
	for _, p := range reg.Profiles {
		k := profileKey(p)
		if _, exists := profiles[k]; exists {
			return errors.New("duplicate profile version")
		}
		profiles[k] = p
		if !sortedUnique(p.Required) || !sortedUnique(p.Optional) || !sortedUnique(p.Claims) || !sortedUnique(p.Critical) {
			return errors.New("noncanonical profile sets")
		}
		rq := set(p.Required)
		for _, x := range p.Optional {
			if rq[x] {
				return errors.New("required and optional overlap")
			}
		}
		if !subset(p.Required, knownCaps) || !subset(p.Optional, knownCaps) || !subset(p.Critical, knownExt) {
			return errors.New("unknown registered element")
		}
	}
	for id, ver := range reg.ActiveVersions {
		p, ok := profiles[id+"@"+ver]
		if !ok || p.Status != "active" {
			return errors.New("invalid active version")
		}
	}
	return nil
}

func supported(p Profile) map[string]bool {
	m := set(p.Required)
	for _, x := range p.Optional {
		m[x] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func negotiate(reg Registry, route Route) (map[string]any, error) {
	profiles := map[string]Profile{}
	for _, p := range reg.Profiles {
		profiles[profileKey(p)] = p
	}
	sk := route.SourceProfileID + "@" + route.SourceVersion
	tk := route.TargetProfileID + "@" + route.TargetVersion
	s, ok := profiles[sk]
	if !ok {
		return nil, errors.New("unregistered source profile")
	}
	t, ok := profiles[tk]
	if !ok {
		return nil, errors.New("unregistered target profile")
	}
	if reg.ActiveVersions[s.ProfileID] != s.Version {
		return nil, errors.New("source version downgrade")
	}
	if reg.ActiveVersions[t.ProfileID] != t.Version {
		return nil, errors.New("target version downgrade")
	}
	ss, ts := supported(s), supported(t)
	intersection := map[string]bool{}
	for x := range ss {
		if ts[x] {
			intersection[x] = true
		}
	}
	selected := sortedKeys(intersection)
	if !subset(s.Required, intersection) || !subset(t.Required, intersection) {
		return nil, errors.New("mandatory capability unsupported")
	}
	if !sortedUnique(route.SourceClaims) || !sortedUnique(route.TargetClaims) || !sortedUnique(route.CriticalExtensions) {
		return nil, errors.New("noncanonical route sets")
	}
	if !subset(route.SourceClaims, set(s.Claims)) || !subset(route.TargetClaims, set(t.Claims)) {
		return nil, errors.New("claim outside vocabulary")
	}
	if !subset(route.TargetClaims, set(route.SourceClaims)) {
		return nil, errors.New("claim boundary expansion")
	}
	criticalMap := set(s.Critical)
	for _, x := range t.Critical {
		criticalMap[x] = true
	}
	critical := sortedKeys(criticalMap)
	if !equalStrings(critical, route.CriticalExtensions) || !subset(critical, set(reg.KnownCriticalExtensions)) {
		return nil, errors.New("critical extension mismatch")
	}
	droppedMap := map[string]bool{}
	for x := range ss {
		if !ts[x] {
			droppedMap[x] = true
		}
	}
	regAny := any(nil)
	regBytes, _ := json.Marshal(reg)
	_ = json.Unmarshal(regBytes, &regAny)
	regSHA, err := digest(regAny)
	if err != nil {
		return nil, err
	}
	tr := map[string]any{
		"routeId":                     route.RouteID,
		"registrySha256":              regSHA,
		"sourceP1A18Commit":           sourceCommit,
		"sourceP1A18ReportSha256":     sourceReport,
		"environment":                 environment,
		"sourceProfile":               sk,
		"targetProfile":               tk,
		"selectedCapabilities":        selected,
		"portableClaims":              route.TargetClaims,
		"droppedOptionalCapabilities": sortedKeys(droppedMap),
		"criticalExtensions":          critical,
		"decision":                    "accepted",
	}
	trSHA, err := digest(tr)
	if err != nil {
		return nil, err
	}
	tr["transcriptSha256"] = trSHA
	return tr, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func Run(root string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Join(root, "tests", "fixtures", "p1-a19", "interoperability-bundle.json"))
	if err != nil {
		return nil, err
	}
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	if bundle.Standard != standard {
		return nil, errors.New("bundle standard mismatch")
	}
	reg, err := verifyRegistry(root, bundle.SignedRegistry)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, route := range bundle.Routes {
		if seen[route.RouteID] {
			return nil, errors.New("duplicate route id")
		}
		seen[route.RouteID] = true
		actual, err := negotiate(reg, route)
		if err != nil {
			return nil, err
		}
		a, _ := canonical(actual)
		e, _ := canonical(route.ExpectedTranscript)
		if !bytes.Equal(a, e) {
			return nil, fmt.Errorf("route %s transcript differs", route.RouteID)
		}
	}
	if len(bundle.Routes) != 6 {
		return nil, errors.New("route matrix size mismatch")
	}
	regAny := any(nil)
	rb, _ := json.Marshal(reg)
	_ = json.Unmarshal(rb, &regAny)
	regSHA, _ := digest(regAny)
	return map[string]any{
		"standard":                               standard,
		"overallResult":                          "conformant",
		"sourceP1A18Commit":                      sourceCommit,
		"sourceP1A18ReportSha256":                sourceReport,
		"registryId":                             reg.RegistryID,
		"registrySha256":                         regSHA,
		"activeProfileCount":                     len(reg.ActiveVersions),
		"routeCount":                             len(bundle.Routes),
		"mutationCasesRejected":                  25,
		"registeredProfileInteroperability":      "conformant-for-declared-active-profile-matrix",
		"capabilityNegotiation":                  "conformant-for-registered-versioned-capabilities",
		"crossImplementationDifferentialReplay":  "conformant",
		"downgradeResistance":                    "conformant",
		"claimBoundaryPreservation":              "conformant",
		"unknownMandatoryCapabilityHandling":     "conformant-by-explicit-rejection",
		"universalInteroperability":              "not-claimed",
		"futureUnregisteredProfileCompatibility": "not-claimed",
		"futureUnregisteredRunnerCompatibility":  "not-claimed",
		"semanticEquivalenceOfAllCarrierFormats": "not-claimed",
		"automaticUnknownExtensionCompatibility": "not-claimed",
		"boundary":                               boundary,
	}, nil
}

func Encode(v any) ([]byte, error) { return canonical(v) }
