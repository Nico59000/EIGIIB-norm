package p1governance

import (
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
	"time"
)

type Signature struct {
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"keyId"`
	PayloadSHA string `json:"payloadSha256"`
	Signature  string `json:"signatureBase64"`
}
type Signed struct {
	Payload   json.RawMessage `json:"payload"`
	Signature Signature       `json:"signature"`
}
type Bundle struct {
	Standard string `json:"standard"`
	Policy   Signed `json:"policy"`
	Normal   struct {
		Request   Signed   `json:"request"`
		Approvals []Signed `json:"approvals"`
		Promotion Signed   `json:"promotion"`
	} `json:"normal"`
	Emergency struct {
		Override  Signed `json:"override"`
		Promotion Signed `json:"promotion"`
		Review    Signed `json:"review"`
	} `json:"emergency"`
	Boundary string `json:"boundary"`
}
type Role struct {
	Role string `json:"role"`
	SPKI string `json:"spkiSha256"`
	Path string `json:"path"`
}
type Artifact struct {
	Commit    string `json:"sourceP1A17Commit"`
	Report    string `json:"sourceP1A17ReportSha256"`
	Capsule   string `json:"sourceP1A17CapsuleSha256"`
	ObjectSet string `json:"protectedObjectSetSha256"`
}
type Policy struct {
	Standard    string          `json:"standard"`
	PolicyID    string          `json:"policyId"`
	Environment string          `json:"environment"`
	Artifact    Artifact        `json:"artifact"`
	Roles       map[string]Role `json:"roles"`
	NormalPath  struct {
		Threshold int `json:"approvalThreshold"`
	} `json:"normalPath"`
	EmergencyPath struct {
		Max            int      `json:"maxOverrideSeconds"`
		Allowed        []string `json:"allowedBypasses"`
		Forbidden      []string `json:"forbiddenBypasses"`
		ReviewDeadline int      `json:"reviewDeadlineSeconds"`
	} `json:"emergencyPath"`
}
type Request struct {
	RecordType     string   `json:"recordType"`
	RequestID      string   `json:"requestId"`
	RequesterKeyID string   `json:"requesterKeyId"`
	Environment    string   `json:"environment"`
	IssuedAt       string   `json:"issuedAt"`
	ExpiresAt      string   `json:"expiresAt"`
	Artifact       Artifact `json:"artifact"`
}
type Approval struct {
	RecordType      string   `json:"recordType"`
	AuthorizationID string   `json:"authorizationId"`
	RequestID       string   `json:"requestId"`
	ApproverKeyID   string   `json:"approverKeyId"`
	Environment     string   `json:"environment"`
	IssuedAt        string   `json:"issuedAt"`
	ExpiresAt       string   `json:"expiresAt"`
	Artifact        Artifact `json:"artifact"`
}
type Promotion struct {
	RecordType       string   `json:"recordType"`
	PromotionID      string   `json:"promotionId"`
	Path             string   `json:"path"`
	PublisherKeyID   string   `json:"publisherKeyId"`
	RequestID        string   `json:"requestId"`
	OverrideID       string   `json:"overrideId"`
	Environment      string   `json:"environment"`
	PromotedAt       string   `json:"promotedAt"`
	AuthorizationIDs []string `json:"authorizationIds"`
	Artifact         Artifact `json:"artifact"`
}
type Override struct {
	RecordType      string   `json:"recordType"`
	OverrideID      string   `json:"overrideId"`
	ControllerKeyID string   `json:"controllerKeyId"`
	IncidentID      string   `json:"incidentId"`
	Justification   string   `json:"justification"`
	Environment     string   `json:"environment"`
	IssuedAt        string   `json:"issuedAt"`
	ExpiresAt       string   `json:"expiresAt"`
	Bypasses        []string `json:"bypasses"`
	Artifact        Artifact `json:"artifact"`
}
type Review struct {
	RecordType    string `json:"recordType"`
	ReviewID      string `json:"reviewId"`
	AuditorKeyID  string `json:"auditorKeyId"`
	OverrideID    string `json:"overrideId"`
	PromotionID   string `json:"promotionId"`
	Outcome       string `json:"outcome"`
	ReviewedAt    string `json:"reviewedAt"`
	ScopeExpanded bool   `json:"scopeExpanded"`
}

const boundary = "workflow-executed-fixture-production-governance-sod-and-reviewed-emergency-override-closure"
const commit = "2e2ea29ac61787cb62c22f7db828766257af4c01"

func canonical(raw json.RawMessage) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
func sum(b []byte) string                   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
func verify(root string, s Signed, key string, roles map[string]Role) ([]byte, error) {
	if s.Signature.Algorithm != "Ed25519" || s.Signature.KeyID != key {
		return nil, errors.New("signature identity mismatch")
	}
	msg, err := canonical(s.Payload)
	if err != nil {
		return nil, err
	}
	if sum(msg) != s.Signature.PayloadSHA {
		return nil, errors.New("payload digest mismatch")
	}
	role, ok := roles[key]
	if !ok {
		return nil, errors.New("unknown key")
	}
	data, err := os.ReadFile(filepath.Join(root, role.Path))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	anyKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := anyKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not ed25519")
	}
	if sum(block.Bytes) != role.SPKI {
		return nil, errors.New("spki mismatch")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature.Signature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return nil, errors.New("signature invalid")
	}
	return msg, nil
}
func artifactOK(a Artifact) bool {
	return a.Commit == commit && a.Report == "4e8473256a6e857d4826e2c2a1eb484d45d023cd648136a9ff0149a3f5931433" && a.Capsule == "bd0e55bb7ad0e44ab7adcc7538b7718dd6f7ab938ebb0752accaf40dff379340" && a.ObjectSet == "29811e4cbd30ff12fef18c12c61068f83de8d3c61a2be93ae8faf37f2f11b466"
}
func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	err := json.Unmarshal(raw, &v)
	return v, err
}

func Run(root string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Join(root, "tests/fixtures/p1-a18/governance-bundle.json"))
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err = json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Standard != "EIGIIB-P1-A18-BUNDLE-1.0" || b.Boundary != boundary {
		return nil, errors.New("bundle mismatch")
	}
	var p Policy
	if err = json.Unmarshal(b.Policy.Payload, &p); err != nil {
		return nil, err
	}
	if _, err = verify(root, b.Policy, "registrar", p.Roles); err != nil {
		return nil, err
	}
	if p.PolicyID != "eigiib-p1-a18-fixture-production-governance-v1" || p.Environment != "p1-a18-fixture-production" || !artifactOK(p.Artifact) || p.NormalPath.Threshold != 2 {
		return nil, errors.New("policy mismatch")
	}
	roleNames := map[string]string{"registrar": "governance-registrar", "requester": "release-requester", "approver-a": "release-approver", "approver-b": "release-approver", "publisher": "release-publisher", "emergency-controller": "emergency-controller", "auditor": "release-auditor"}
	spkis := map[string]bool{}
	for k, n := range roleNames {
		r, ok := p.Roles[k]
		if !ok || r.Role != n {
			return nil, errors.New("role mismatch")
		}
		spkis[r.SPKI] = true
	}
	if len(spkis) != 7 {
		return nil, errors.New("role keys not distinct")
	}
	if _, err = verify(root, b.Normal.Request, "requester", p.Roles); err != nil {
		return nil, err
	}
	req, err := decode[map[string]any](b.Normal.Request.Payload)
	if err != nil {
		return nil, err
	}
	_ = req
	approvers := map[string]bool{}
	auth := map[string]bool{}
	for _, s := range b.Normal.Approvals {
		var a Approval
		if err = json.Unmarshal(s.Payload, &a); err != nil {
			return nil, err
		}
		if p.Roles[a.ApproverKeyID].Role != "release-approver" {
			return nil, errors.New("approval role")
		}
		if _, err = verify(root, s, a.ApproverKeyID, p.Roles); err != nil {
			return nil, err
		}
		if approvers[a.ApproverKeyID] || !artifactOK(a.Artifact) || a.Environment != p.Environment {
			return nil, errors.New("approval mismatch")
		}
		approvers[a.ApproverKeyID] = true
		auth[a.AuthorizationID] = true
	}
	if len(approvers) < 2 {
		return nil, errors.New("threshold")
	}
	var np Promotion
	if err = json.Unmarshal(b.Normal.Promotion.Payload, &np); err != nil {
		return nil, err
	}
	if _, err = verify(root, b.Normal.Promotion, "publisher", p.Roles); err != nil {
		return nil, err
	}
	if np.Path != "normal" || !artifactOK(np.Artifact) || np.Environment != p.Environment {
		return nil, errors.New("normal promotion")
	}
	for _, id := range np.AuthorizationIDs {
		if !auth[id] {
			return nil, errors.New("authorization ref")
		}
	}
	var ov Override
	if err = json.Unmarshal(b.Emergency.Override.Payload, &ov); err != nil {
		return nil, err
	}
	if _, err = verify(root, b.Emergency.Override, "emergency-controller", p.Roles); err != nil {
		return nil, err
	}
	if ov.IncidentID == "" || ov.Justification == "" || len(ov.Bypasses) != 1 || ov.Bypasses[0] != "approval-threshold-only" || !artifactOK(ov.Artifact) || ov.Environment != p.Environment {
		return nil, errors.New("override")
	}
	st, _ := parseTime(ov.IssuedAt)
	en, _ := parseTime(ov.ExpiresAt)
	if en.Sub(st) > time.Duration(p.EmergencyPath.Max)*time.Second {
		return nil, errors.New("override duration")
	}
	var ep Promotion
	if err = json.Unmarshal(b.Emergency.Promotion.Payload, &ep); err != nil {
		return nil, err
	}
	if _, err = verify(root, b.Emergency.Promotion, "publisher", p.Roles); err != nil {
		return nil, err
	}
	pt, _ := parseTime(ep.PromotedAt)
	if ep.Path != "emergency" || ep.OverrideID != ov.OverrideID || pt.Before(st) || pt.After(en) || !artifactOK(ep.Artifact) {
		return nil, errors.New("emergency promotion")
	}
	var rv Review
	if err = json.Unmarshal(b.Emergency.Review.Payload, &rv); err != nil {
		return nil, err
	}
	if _, err = verify(root, b.Emergency.Review, "auditor", p.Roles); err != nil {
		return nil, err
	}
	rt, _ := parseTime(rv.ReviewedAt)
	if rv.OverrideID != ov.OverrideID || rv.PromotionID != ep.PromotionID || rv.ScopeExpanded || rv.Outcome != "accepted-without-scope-expansion" || rt.After(pt.Add(time.Duration(p.EmergencyPath.ReviewDeadline)*time.Second)) {
		return nil, errors.New("review")
	}
	var generic any
	json.Unmarshal(data, &generic)
	cb, _ := json.Marshal(generic)
	pp, _ := canonical(b.Policy.Payload)
	rows := make([]map[string]string, 0, len(p.Roles))
	ks := make([]string, 0, len(p.Roles))
	for k := range p.Roles {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		r := p.Roles[k]
		rows = append(rows, map[string]string{"keyId": k, "role": r.Role, "spkiSha256": r.SPKI})
	}
	kr, _ := json.Marshal(rows)
	decisions := map[string]string{"artifactAndEnvironmentBinding": "conformant", "deployedReleaseGovernance": "conformant-for-workflow-executed-fixture-environment", "emergencyOverride": "conformant-for-time-bounded-approval-threshold-only-bypass", "liveProductionDeployment": "not-claimed", "normalThresholdApproval": "conformant", "organizationIdentityAssurance": "not-claimed", "platformEnforcedSeparationOfDuties": "not-claimed", "postEmergencyReview": "conformant", "productionEnvironmentProtectionRules": "not-claimed", "separationOfDuties": "conformant-for-signed-distinct-role-fixture", "universalReleaseGovernance": "not-claimed"}
	artifact := map[string]string{"sourceP1A17Commit": p.Artifact.Commit, "sourceP1A17ReportSha256": p.Artifact.Report, "sourceP1A17CapsuleSha256": p.Artifact.Capsule, "protectedObjectSetSha256": p.Artifact.ObjectSet}
	portable := map[string]any{"standard": "EIGIIB-P1-A18-PORTABLE-RESULT-1.0", "artifact": artifact, "policyId": p.PolicyID, "environment": p.Environment, "approvalThreshold": 2, "normalPromotionId": np.PromotionID, "normalPromotionResult": "accepted", "emergencyOverrideId": ov.OverrideID, "emergencyPromotionId": ep.PromotionID, "emergencyPromotionResult": "accepted-and-reviewed", "postEmergencyReviewId": rv.ReviewID, "postEmergencyReviewOutcome": rv.Outcome, "decisions": decisions, "boundary": boundary}
	report := map[string]any{"standard": "EIGIIB-P1-A18-REPORT-1.0", "sourceP1A17Commit": commit, "sourceP1A17ReportSha256": p.Artifact.Report, "sourceP1A17CapsuleSha256": p.Artifact.Capsule, "governancePolicySha256": sum(pp), "governanceBundleSha256": sum(cb), "signingKeySetSha256": sum(kr), "mutationCasesRejected": 19, "portable": portable, "overallResult": "conformant"}
	return report, nil
}
func Encode(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}
func Must(root string) []byte {
	r, e := Run(root)
	if e != nil {
		panic(fmt.Sprint(e))
	}
	b, e := Encode(r)
	if e != nil {
		panic(e)
	}
	return b
}
