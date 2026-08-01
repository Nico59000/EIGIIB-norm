package p1remediation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

const (
	standard                 = "EIGIIB-P1-A14-1.0"
	profile                  = "registered-advisory-remediation-fixed-release-v1"
	policyType               = "application/vnd.eigiib.remediation-control-policy+json"
	advisoryType             = "application/vnd.eigiib.security-advisory+json"
	remediationType          = "application/vnd.eigiib.remediation-lineage+json"
	fixedReleaseType         = "application/vnd.eigiib.fixed-release+json"
	candidateType            = "application/vnd.eigiib.fixed-release-candidate+json"
	sourceCommit             = "077634971f2c16f3f74eb4c6c5b75aa7099bee55"
	a13ReportSHA             = "7cbae1b7b686149b91bcea58d365e0700155185e78ac213913a0f3f07943e70b"
	a13CapsuleSHA            = "fb596478e6cad8fe4c8db9e95d54f138cb37f9452a32d938e3d2796ab49240f5"
	a13RevocationEnvelopeSHA = "f15badfb9b3c36468f2f8af72be9fa8263731d334b8a55526079cccfe94ea9ed"
	a13Boundary              = "registered-content-revocation-distribution-withdrawal-anti-rollback-closure"
	trustedEffectiveTime     = 1785603600
	revokedReleaseID         = "eigiib-p1-a7-authority-1.0"
	revokedDescriptorSHA     = "1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec"
	revokedArchiveSHA        = "0e3ce06e9ef4f9299ad5ade9182d3924704248230d924bec656562d58287960e"
	revocationID             = "eigiib-p1-a13-revocation-1"
	revocationSequence       = 31
	policyID                 = "eigiib-p1-a14-remediation-policy-1"
	policySequence           = 40
	advisoryID               = "EIGIIB-SA-FIXTURE-2026-0001"
	advisorySequence         = 41
	remediationID            = "eigiib-p1-a14-remediation-1"
	remediationSequence      = 42
	fixedReleaseID           = "eigiib-p1-a14-fixed-1.1"
	fixedReleaseVersion      = "1.1.0"
	fixedReleaseSequence     = 43
	boundary                 = "registered-advisory-remediation-lineage-fixed-release-replay-closure"
)

var sourceAcceptedHistory = []any{
	"policy-sequence-30",
	"revocation-sequence-31",
	"fixture-primary-withdrawal-sequence-32",
	"fixture-mirror-withdrawal-sequence-33",
}

var revokedContent = map[string]any{
	"archiveSha256":           revokedArchiveSHA,
	"releaseDescriptorSha256": revokedDescriptorSHA,
	"releaseId":               revokedReleaseID,
}

var vulnerabilityIDs = []any{"EIGIIB-FIXTURE-VULN-2026-0001"}

var claimBoundary = []any{
	"advisory-binding-does-not-prove-an-external-vulnerability-assignment",
	"remediation-lineage-does-not-independently-prove-semantic-defect-removal",
	"fixed-release-identity-does-not-prove-production-release-authorization",
	"fixture-replay-does-not-prove-live-github-or-registry-publication",
	"accepted-fixed-release-does-not-unrevoke-the-predecessor-content",
	"exact-digest-equality-does-not-prove-universal-interoperability",
	"fixture-authorities-do-not-prove-real-world-organizational-control",
	"p1-a14-does-not-establish-global-availability-or-durable-persistence",
}

type Verifier func(raw, payload []byte, contentType string, key ed25519.PublicKey, der []byte) error

type artifactSet struct {
	archive    map[string]any
	changeSet  map[string]any
	content    map[string]any
	descriptor map[string]any
}

func sha(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func fieldString(m map[string]any, key string) (string, error) {
	value, ok := str(m[key])
	if !ok {
		return "", fmt.Errorf("%s string", key)
	}
	return value, nil
}

func signed(value any, expected map[string]any, contentType string, key ed25519.PublicKey, der []byte, verify Verifier) ([]byte, error) {
	carrier, ok := obj(value)
	if !ok || !requireKeys(carrier, "payload", "envelope") {
		return nil, errors.New("signed carrier")
	}
	payload, err := carrierBytes(carrier["payload"])
	if err != nil {
		return nil, err
	}
	want, err := canonicalJSON(expected)
	if err != nil || !bytes.Equal(payload, want) {
		return nil, errors.New("signed semantics")
	}
	envelope, err := carrierBytes(carrier["envelope"])
	if err != nil {
		return nil, err
	}
	if err = verify(envelope, payload, contentType, key, der); err != nil {
		return nil, err
	}
	return envelope, nil
}

func sourceAuthority(root string) (map[string]any, map[string]any, error) {
	reportRaw, _, err := safeRead(root, "tests/fixtures/p1-a13/expected-report.json")
	if err != nil {
		return nil, nil, err
	}
	if sha(reportRaw) != a13ReportSHA {
		return nil, nil, errors.New("A13 report identity")
	}
	reportValue, err := strictJSON(reportRaw)
	if err != nil {
		return nil, nil, err
	}
	report, ok := obj(reportValue)
	if !ok || report["overall_result"] != "conformant" || report["boundary"] != a13Boundary {
		return nil, nil, errors.New("A13 report")
	}
	if report["release_id"] != revokedReleaseID || report["release_descriptor_sha256"] != revokedDescriptorSHA || report["content_archive_sha256"] != revokedArchiveSHA {
		return nil, nil, errors.New("A13 revoked content")
	}
	if report["revocation_id"] != revocationID || report["vulnerability_remediation_result"] != "not-claimed" {
		return nil, nil, errors.New("A13 revocation result")
	}
	sequence, ok := integer(report["revocation_sequence"])
	if !ok || sequence != revocationSequence || !sameJSON(report["accepted_history"], sourceAcceptedHistory) {
		return nil, nil, errors.New("A13 sequence or history")
	}

	capsuleRaw, _, err := safeRead(root, "tests/fixtures/p1-a13/capsule.json")
	if err != nil {
		return nil, nil, err
	}
	if sha(capsuleRaw) != a13CapsuleSHA {
		return nil, nil, errors.New("A13 capsule identity")
	}
	capsuleValue, err := strictJSON(capsuleRaw)
	if err != nil {
		return nil, nil, err
	}
	capsule, ok := obj(capsuleValue)
	if !ok {
		return nil, nil, errors.New("A13 capsule")
	}
	revocation, ok := obj(capsule["revocation"])
	if !ok {
		return nil, nil, errors.New("A13 revocation carrier")
	}
	envelope, err := carrierBytes(revocation["envelope"])
	if err != nil {
		return nil, nil, err
	}
	revocationEnvelope := identity(envelope)
	if revocationEnvelope["digest"] != a13RevocationEnvelopeSHA {
		return nil, nil, errors.New("A13 revocation envelope")
	}

	stateRaw, _, err := safeRead(root, "conformance/p1-a13-revocation.json")
	if err != nil {
		return nil, nil, err
	}
	stateValue, err := strictJSON(stateRaw)
	if err != nil {
		return nil, nil, err
	}
	state, ok := obj(stateValue)
	if !ok || state["capsule_sha256"] != a13CapsuleSHA || state["boundary"] != a13Boundary {
		return nil, nil, errors.New("A13 conformance state")
	}

	source := map[string]any{
		"acceptedHistory":          sourceAcceptedHistory,
		"archiveSha256":            revokedArchiveSHA,
		"boundary":                 a13Boundary,
		"releaseDescriptorSha256":  revokedDescriptorSHA,
		"releaseId":                revokedReleaseID,
		"revocationCapsuleSha256":  a13CapsuleSHA,
		"revocationEnvelope":       revocationEnvelope,
		"revocationId":             revocationID,
		"revocationReportSha256":   a13ReportSHA,
		"revocationSequence":       revocationSequence,
		"sourceCommit":             sourceCommit,
		"trustedEffectiveTimeUnix": trustedEffectiveTime,
	}
	return source, revocationEnvelope, nil
}

func artifact(root, path string) ([]byte, map[string]any, error) {
	raw, _, err := safeRead(root, path)
	if err != nil {
		return nil, nil, err
	}
	return raw, map[string]any{"path": path, "identity": identity(raw)}, nil
}

func fixtureArtifacts(root string) (artifactSet, error) {
	archiveRaw, archive, err := artifact(root, "tests/fixtures/p1-a14/fixed-release-archive.txt")
	if err != nil {
		return artifactSet{}, err
	}
	changeRaw, changeSet, err := artifact(root, "tests/fixtures/p1-a14/remediation-change-set.json")
	if err != nil {
		return artifactSet{}, err
	}
	expectedChange := map[string]any{
		"changes": []any{
			"reject-revoked-fixture-content",
			"bind-parser-state-to-fixed-release",
			"preserve-predecessor-revocation-floor",
		},
		"fixtureOnly":      true,
		"standard":         "EIGIIB-P1-A14-CHANGESET-1.0",
		"vulnerabilityIds": vulnerabilityIDs,
	}
	changeValue, err := decodeCanonical(changeRaw)
	if err != nil || !sameJSON(changeValue, expectedChange) {
		return artifactSet{}, errors.New("change-set artifact")
	}
	descriptorRaw, descriptor, err := artifact(root, "tests/fixtures/p1-a14/fixed-release-descriptor.json")
	if err != nil {
		return artifactSet{}, err
	}
	expectedDescriptor := map[string]any{
		"advisoryId":  advisoryID,
		"archive":     archive,
		"changeSet":   changeSet,
		"predecessor": revokedContent,
		"releaseId":   fixedReleaseID,
		"standard":    "EIGIIB-P1-A14-FIXED-RELEASE-DESCRIPTOR-1.0",
		"version":     fixedReleaseVersion,
	}
	descriptorValue, err := decodeCanonical(descriptorRaw)
	if err != nil || !sameJSON(descriptorValue, expectedDescriptor) {
		return artifactSet{}, errors.New("fixed-release descriptor artifact")
	}
	content := map[string]any{
		"archiveSha256":           sha(archiveRaw),
		"releaseDescriptorSha256": sha(descriptorRaw),
		"releaseId":               fixedReleaseID,
	}
	return artifactSet{archive: archive, changeSet: changeSet, content: content, descriptor: descriptor}, nil
}

func policyExpected(source, rootSPKI, advisoryAuthority, remediationAuthority, fixedSigner map[string]any) map[string]any {
	return map[string]any{
		"action":             "register-remediation-policy",
		"advisoryAuthority":  advisoryAuthority,
		"claimBoundary":      map[string]any{"doesNotImply": claimBoundary},
		"fixedReleaseSigner": fixedSigner,
		"lineagePolicy": map[string]any{
			"advisoryMustBindExactRevokedContent":            true,
			"exactAdvisoryAndRemediationBindingsRequired":    true,
			"fixedReleaseFloorSequence":                      fixedReleaseSequence,
			"idempotentExactReplayDoesNotAdvanceHistory":     true,
			"revokedPredecessorRemainsRejected":              true,
			"sameReleaseIdRequiresExactDescriptorAndArchive": true,
		},
		"policyId":                   policyID,
		"policySequence":             policySequence,
		"remediationAuthority":       remediationAuthority,
		"remediationControlRootSpki": rootSPKI,
		"sourceAuthority":            source,
		"standard":                   "EIGIIB-P1-A14-POLICY-1.0",
	}
}

func copyIdentity(value map[string]any) map[string]any {
	return map[string]any{"algorithm": value["algorithm"], "bytes": value["bytes"], "digest": value["digest"]}
}

func candidateExpected(id string, sequence int, contentMode, bindingMode string, artifacts artifactSet, policyIdentity, advisoryIdentity, remediationIdentity map[string]any, index int) (map[string]any, error) {
	content := map[string]any{
		"archiveSha256":           artifacts.content["archiveSha256"],
		"releaseDescriptorSha256": artifacts.content["releaseDescriptorSha256"],
		"releaseId":               artifacts.content["releaseId"],
	}
	switch contentMode {
	case "revoked":
		content = map[string]any{
			"archiveSha256":           revokedArchiveSHA,
			"releaseDescriptorSha256": revokedDescriptorSHA,
			"releaseId":               revokedReleaseID,
		}
	case "altered-archive":
		content["archiveSha256"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "exact":
	default:
		return nil, errors.New("candidate content mode")
	}
	advisory := copyIdentity(advisoryIdentity)
	switch bindingMode {
	case "wrong-advisory":
		advisory["digest"] = "0000000000000000000000000000000000000000000000000000000000000000"
	case "exact":
	default:
		return nil, errors.New("candidate binding mode")
	}
	return map[string]any{
		"action":              "observe-fixed-release-candidate",
		"advisoryEnvelope":    advisory,
		"candidateId":         id,
		"candidateSequence":   sequence,
		"content":             content,
		"observedAtUnix":      1785621600 + index*60,
		"policyEnvelope":      policyIdentity,
		"remediationEnvelope": remediationIdentity,
		"standard":            "EIGIIB-P1-A14-CANDIDATE-1.0",
	}, nil
}

func Evaluate(root, capsulePath string) (map[string]any, error) {
	return EvaluateWithVerifier(root, capsulePath, verifyCOSE)
}

func EvaluateWithVerifier(root, capsulePath string, verify Verifier) (map[string]any, error) {
	source, sourceRevocationEnvelope, err := sourceAuthority(root)
	if err != nil {
		return nil, err
	}
	artifacts, err := fixtureArtifacts(root)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(capsulePath)
	if err != nil {
		return nil, err
	}
	value, err := decodeCanonical(raw)
	if err != nil {
		return nil, err
	}
	capsule, ok := obj(value)
	if !ok || !requireKeys(capsule,
		"standard", "profile", "sourceAuthority", "remediationControlRoot",
		"advisoryAuthority", "remediationAuthority", "fixedReleaseSigner",
		"policy", "advisory", "remediation", "fixedRelease", "replays", "claimBoundary") {
		return nil, errors.New("capsule")
	}
	if capsule["standard"] != standard || capsule["profile"] != profile || !sameJSON(capsule["sourceAuthority"], source) || !sameJSON(capsule["claimBoundary"], claimBoundary) {
		return nil, errors.New("capsule constants")
	}

	rootCarrier, ok := obj(capsule["remediationControlRoot"])
	if !ok || !requireKeys(rootCarrier, "path", "spki") {
		return nil, errors.New("root carrier")
	}
	rootKey, rootDER, err := readKey(root, rootCarrier, []string{"path", "spki"})
	if err != nil {
		return nil, err
	}

	advisoryCarrier, ok := obj(capsule["advisoryAuthority"])
	if !ok || !requireKeys(advisoryCarrier, "id", "path", "spki") {
		return nil, errors.New("advisory authority")
	}
	advisoryIDValue, _ := fieldString(advisoryCarrier, "id")
	if advisoryIDValue != "eigiib-p1-a14-advisory-issuer-1" {
		return nil, errors.New("advisory authority id")
	}
	advisoryKey, advisoryDER, err := readKey(root, advisoryCarrier, []string{"id", "path", "spki"})
	if err != nil {
		return nil, err
	}

	remediationCarrier, ok := obj(capsule["remediationAuthority"])
	if !ok || !requireKeys(remediationCarrier, "id", "path", "spki") {
		return nil, errors.New("remediation authority")
	}
	remediationIDValue, _ := fieldString(remediationCarrier, "id")
	if remediationIDValue != "eigiib-p1-a14-remediator-1" {
		return nil, errors.New("remediation authority id")
	}
	remediationKey, remediationDER, err := readKey(root, remediationCarrier, []string{"id", "path", "spki"})
	if err != nil {
		return nil, err
	}

	signerCarrier, ok := obj(capsule["fixedReleaseSigner"])
	if !ok || !requireKeys(signerCarrier, "id", "path", "spki") {
		return nil, errors.New("fixed release signer")
	}
	signerIDValue, _ := fieldString(signerCarrier, "id")
	if signerIDValue != "eigiib-p1-a14-fixed-release-signer-1" {
		return nil, errors.New("fixed release signer id")
	}
	signerKey, signerDER, err := readKey(root, signerCarrier, []string{"id", "path", "spki"})
	if err != nil {
		return nil, err
	}

	advisoryAuthority := map[string]any{"id": advisoryIDValue, "spki": identity(advisoryDER)}
	remediationAuthority := map[string]any{"id": remediationIDValue, "spki": identity(remediationDER)}
	fixedSigner := map[string]any{"id": signerIDValue, "spki": identity(signerDER)}

	policyEnvelope, err := signed(capsule["policy"], policyExpected(source, identity(rootDER), advisoryAuthority, remediationAuthority, fixedSigner), policyType, rootKey, rootDER, verify)
	if err != nil {
		return nil, err
	}
	policyIdentity := identity(policyEnvelope)

	advisoryExpected := map[string]any{
		"action":                   "issue-security-advisory",
		"advisoryId":               advisoryID,
		"advisorySequence":         advisorySequence,
		"affectedContent":          revokedContent,
		"issuedAtUnix":             1785610800,
		"policyEnvelope":           policyIdentity,
		"severity":                 "high",
		"sourceRevocationEnvelope": sourceRevocationEnvelope,
		"standard":                 "EIGIIB-P1-A14-ADVISORY-1.0",
		"status":                   "confirmed-for-fixture-scope",
		"vulnerabilityIds":         vulnerabilityIDs,
	}
	advisoryEnvelope, err := signed(capsule["advisory"], advisoryExpected, advisoryType, advisoryKey, advisoryDER, verify)
	if err != nil {
		return nil, err
	}
	advisoryIdentity := identity(advisoryEnvelope)

	remediationExpected := map[string]any{
		"action":                         "bind-remediation-lineage",
		"advisoryEnvelope":               advisoryIdentity,
		"changeSetArtifact":              artifacts.changeSet,
		"effectiveTimeUnix":              1785614400,
		"fixedContent":                   artifacts.content,
		"fixedReleaseDescriptorArtifact": artifacts.descriptor,
		"policyEnvelope":                 policyIdentity,
		"predecessorContent":             revokedContent,
		"remediationClass":               "replacement-release",
		"remediationId":                  remediationID,
		"remediationSequence":            remediationSequence,
		"sourceRevocationEnvelope":       sourceRevocationEnvelope,
		"standard":                       "EIGIIB-P1-A14-REMEDIATION-1.0",
		"validationBasis": []any{
			"exact-advisory-binding",
			"exact-predecessor-and-successor-digests",
			"registered-fixture-authority-signature",
		},
	}
	remediationEnvelope, err := signed(capsule["remediation"], remediationExpected, remediationType, remediationKey, remediationDER, verify)
	if err != nil {
		return nil, err
	}
	remediationIdentity := identity(remediationEnvelope)

	fixedExpected := map[string]any{
		"action":              "issue-fixed-release",
		"advisoryEnvelope":    advisoryIdentity,
		"archiveArtifact":     artifacts.archive,
		"content":             artifacts.content,
		"descriptorArtifact":  artifacts.descriptor,
		"issuedAtUnix":        1785618000,
		"policyEnvelope":      policyIdentity,
		"predecessorContent":  revokedContent,
		"releaseSequence":     fixedReleaseSequence,
		"remediationEnvelope": remediationIdentity,
		"standard":            "EIGIIB-P1-A14-FIXED-RELEASE-1.0",
		"version":             fixedReleaseVersion,
	}
	fixedEnvelope, err := signed(capsule["fixedRelease"], fixedExpected, fixedReleaseType, signerKey, signerDER, verify)
	if err != nil {
		return nil, err
	}

	replays, ok := arr(capsule["replays"])
	if !ok || len(replays) != 5 {
		return nil, errors.New("replays")
	}
	ids := []string{"idempotent-fixed-release", "revoked-predecessor", "same-id-altered-archive", "wrong-advisory-lineage", "below-fixed-release-floor"}
	sequences := []int{43, 44, 45, 46, 42}
	contentModes := []string{"exact", "revoked", "altered-archive", "exact", "exact"}
	bindingModes := []string{"exact", "exact", "exact", "wrong-advisory", "exact"}
	decisions := []string{"accepted-idempotent-fixed-release-replay", "rejected-revoked-predecessor", "rejected-fixed-release-content-substitution", "rejected-advisory-lineage-mismatch", "rejected-below-fixed-release-floor"}
	replayResults := []any{}
	for index, row := range replays {
		carrier, ok := obj(row)
		if !ok || !requireKeys(carrier, "id", "candidate", "expectedDecision") || carrier["id"] != ids[index] || carrier["expectedDecision"] != decisions[index] {
			return nil, errors.New("replay")
		}
		expected, err := candidateExpected(ids[index], sequences[index], contentModes[index], bindingModes[index], artifacts, policyIdentity, advisoryIdentity, remediationIdentity, index)
		if err != nil {
			return nil, err
		}
		if _, err = signed(carrier["candidate"], expected, candidateType, signerKey, signerDER, verify); err != nil {
			return nil, err
		}
		replayResults = append(replayResults, map[string]any{"decision": decisions[index], "id": ids[index], "sequence": sequences[index]})
	}

	acceptedHistory := append([]any{}, sourceAcceptedHistory...)
	acceptedHistory = append(acceptedHistory,
		fmt.Sprintf("remediation-policy-sequence-%d", policySequence),
		fmt.Sprintf("advisory-sequence-%d", advisorySequence),
		fmt.Sprintf("remediation-sequence-%d", remediationSequence),
		fmt.Sprintf("fixed-release-sequence-%d", fixedReleaseSequence),
	)
	return map[string]any{
		"accepted_history":                        acceptedHistory,
		"advisory_binding_result":                 "conformant-for-exact-revoked-content-and-registered-fixture-advisory-scope",
		"advisory_envelope_sha256":                sha(advisoryEnvelope),
		"advisory_id":                             advisoryID,
		"boundary":                                boundary,
		"claim_boundary":                          claimBoundary,
		"fixed_release_archive_sha256":            artifacts.content["archiveSha256"],
		"fixed_release_descriptor_sha256":         artifacts.content["releaseDescriptorSha256"],
		"fixed_release_envelope_sha256":           sha(fixedEnvelope),
		"fixed_release_floor_sequence":            fixedReleaseSequence,
		"fixed_release_id":                        fixedReleaseID,
		"fixed_release_replay_result":             "conformant-for-exact-fixed-release-and-no-history-advance-on-idempotent-replay-scope",
		"live_release_publication_result":         "not-claimed",
		"overall_result":                          "conformant",
		"policy_envelope_sha256":                  sha(policyEnvelope),
		"production_release_authorization_result": "not-claimed",
		"profile": profile,
		"real_world_vulnerability_resolution_result": "not-claimed",
		"remediation_envelope_sha256":                sha(remediationEnvelope),
		"remediation_id":                             remediationID,
		"remediation_lineage_result":                 "conformant-for-exact-revoked-predecessor-to-fixed-successor-fixture-scope",
		"replay_results":                             replayResults,
		"revoked_archive_sha256":                     revokedArchiveSHA,
		"revoked_release_descriptor_sha256":          revokedDescriptorSHA,
		"revoked_release_id":                         revokedReleaseID,
		"source_revocation_capsule_sha256":           a13CapsuleSHA,
		"source_revocation_report_sha256":            a13ReportSHA,
		"standard":                                   standard,
		"tool":                                       "eigiib-p1-a14-remediation-check",
		"tool_version":                               "0.1.0",
		"trusted_effective_time_unix":                trustedEffectiveTime,
		"vulnerability_ids":                          vulnerabilityIDs,
		"vulnerability_remediation_result":           "conformant-for-registered-fixture-advisory-lineage-and-fixed-artifact-identity-scope",
	}, nil
}

func CanonicalResult(result map[string]any) ([]byte, error) {
	return canonicalJSON(result)
}
