package p1revocation

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
	standard             = "EIGIIB-P1-A13-1.0"
	profile              = "registered-content-revocation-withdrawal-anti-rollback-v1"
	policyType           = "application/vnd.eigiib.content-control-policy+json"
	revocationType       = "application/vnd.eigiib.content-revocation+json"
	withdrawalType       = "application/vnd.eigiib.distribution-withdrawal+json"
	observationType      = "application/vnd.eigiib.distribution-observation+json"
	a12ReportSHA         = "7613429f8d3b771812433f5b57d64accb8148550ed9f8b71a38a97b23a45343c"
	a12CapsuleSHA        = "12b3ca6c0ca260b3357993d65a8b4595f6cc23d4b8b26ca67dcee94e06148046"
	releaseID            = "eigiib-p1-a7-authority-1.0"
	releaseDescriptorSHA = "1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec"
	archiveSHA           = "0e3ce06e9ef4f9299ad5ade9182d3924704248230d924bec656562d58287960e"
	recoveredAuthSHA     = "d185060877ac9f63cfb1ae93f1b56aea16307ce090977bbc3e997036ae4a5d01"
	checkpointRoot       = "cbaa2980c0c57054a161f77c34a1300d86f4cd4c04a06fbcdde35ef5d4628641"
	policyID             = "eigiib-p1-a13-content-control-policy-1"
	revocationID         = "eigiib-p1-a13-revocation-1"
	boundary             = "registered-content-revocation-distribution-withdrawal-anti-rollback-closure"
)

var claimBoundary = []any{
	"content-revocation-does-not-erase-published-bytes",
	"registered-channel-withdrawal-does-not-prove-global-unavailability",
	"anti-rollback-does-not-prove-absence-from-unregistered-mirrors",
	"revocation-does-not-establish-vulnerability-remediation",
	"withdrawal-does-not-establish-durable-purge",
	"fixture-control-root-does-not-prove-real-world-operator-identity",
	"p1-a13-does-not-imply-live-github-or-registry-publication",
}
var source = map[string]any{
	"acceptedTransparencyCheckpointRoot": checkpointRoot, "releaseDescriptorSha256": releaseDescriptorSHA,
	"releaseId": releaseID, "recoveredAuthorizationSha256": recoveredAuthSHA,
	"sourceCommit": "286c17db08911ae22202aa30c90cac10dc3c61b8", "transparencyCapsuleSha256": a12CapsuleSHA,
	"transparencyReportSha256": a12ReportSHA, "trustedEffectiveTimeUnix": 1785603600,
}
var content = map[string]any{"archiveSha256": archiveSHA, "releaseDescriptorSha256": releaseDescriptorSHA, "releaseId": releaseID}

type Verifier func(raw, payload []byte, contentType string, key ed25519.PublicKey, der []byte) error

func sha(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func fieldString(m map[string]any, k string) (string, error) {
	v, ok := str(m[k])
	if !ok {
		return "", fmt.Errorf("%s string", k)
	}
	return v, nil
}
func fieldInt(m map[string]any, k string) (int64, error) {
	v, ok := integer(m[k])
	if !ok {
		return 0, fmt.Errorf("%s integer", k)
	}
	return v, nil
}

func verifySource(root string) error {
	raw, _, e := safeRead(root, "tests/fixtures/p1-a12/expected-report.json")
	if e != nil {
		return e
	}
	if sha(raw) != a12ReportSHA {
		return errors.New("A12 report identity")
	}
	v, e := strictJSON(raw)
	if e != nil {
		return e
	}
	m, ok := obj(v)
	if !ok {
		return errors.New("A12 report")
	}
	if m["overall_result"] != "conformant" || m["release_id"] != releaseID || m["recovered_checkpoint_root"] != checkpointRoot {
		return errors.New("A12 report semantics")
	}
	t, ok := integer(m["trusted_effective_time_unix"])
	if !ok || t != 1785603600 {
		return errors.New("A12 time")
	}
	stateRaw, _, e := safeRead(root, "conformance/p1-a12-transparency.json")
	if e != nil {
		return e
	}
	stateV, e := strictJSON(stateRaw)
	if e != nil {
		return e
	}
	state, ok := obj(stateV)
	if !ok || state["capsule_sha256"] != a12CapsuleSHA {
		return errors.New("A12 capsule authority")
	}
	a10Raw, _, e := safeRead(root, "tests/fixtures/p1-a10/expected-report.json")
	if e != nil {
		return e
	}
	a10v, e := strictJSON(a10Raw)
	if e != nil {
		return e
	}
	a10, ok := obj(a10v)
	if !ok || a10["release_descriptor_sha256"] != releaseDescriptorSHA || a10["recovered_authorization_sha256"] != recoveredAuthSHA {
		return errors.New("A10 authority")
	}
	a11Raw, _, e := safeRead(root, "tests/fixtures/p1-a11/expected-report.json")
	if e != nil {
		return e
	}
	a11v, e := strictJSON(a11Raw)
	if e != nil {
		return e
	}
	a11, ok := obj(a11v)
	if !ok || a11["recovered_authorization_sha256"] != recoveredAuthSHA {
		return errors.New("A11 authority")
	}
	at, ok := integer(a11["last_accepted_timestamp_unix"])
	if !ok || at != 1785603600 {
		return errors.New("A11 time")
	}
	return nil
}

func signed(v any, expected map[string]any, contentType string, key ed25519.PublicKey, der []byte, verify Verifier) ([]byte, error) {
	m, ok := obj(v)
	if !ok || !requireKeys(m, "payload", "envelope") {
		return nil, errors.New("signed carrier")
	}
	payload, e := carrierBytes(m["payload"])
	if e != nil {
		return nil, e
	}
	want, e := canonicalJSON(expected)
	if e != nil || !bytes.Equal(payload, want) {
		return nil, errors.New("signed semantics")
	}
	env, e := carrierBytes(m["envelope"])
	if e != nil {
		return nil, e
	}
	if e = verify(env, payload, contentType, key, der); e != nil {
		return nil, e
	}
	return env, nil
}

func Evaluate(root, capsulePath string) (map[string]any, error) {
	return EvaluateWithVerifier(root, capsulePath, verifyCOSE)
}
func EvaluateWithVerifier(root, capsulePath string, verify Verifier) (map[string]any, error) {
	if e := verifySource(root); e != nil {
		return nil, e
	}
	raw, e := os.ReadFile(capsulePath)
	if e != nil {
		return nil, e
	}
	v, e := decodeCanonical(raw)
	if e != nil {
		return nil, e
	}
	cap, ok := obj(v)
	if !ok || !requireKeys(cap, "standard", "profile", "sourceAuthority", "contentControlRoot", "revocationAuthority", "channels", "policy", "revocation", "withdrawals", "replays", "claimBoundary") {
		return nil, errors.New("capsule")
	}
	if cap["standard"] != standard || cap["profile"] != profile || !sameJSON(cap["sourceAuthority"], source) || !sameJSON(cap["claimBoundary"], claimBoundary) {
		return nil, errors.New("capsule constants")
	}
	rootCarrier, ok := obj(cap["contentControlRoot"])
	if !ok {
		return nil, errors.New("root carrier")
	}
	rootKey, rootDER, e := readKey(root, rootCarrier, []string{"path", "spki"})
	if e != nil {
		return nil, e
	}
	revCarrier, ok := obj(cap["revocationAuthority"])
	if !ok {
		return nil, errors.New("revoker carrier")
	}
	rid, e := fieldString(revCarrier, "id")
	if e != nil || rid != "eigiib-p1-a13-revoker-1" {
		return nil, errors.New("revoker id")
	}
	revKey, revDER, e := readKey(root, revCarrier, []string{"id", "path", "spki"})
	if e != nil {
		return nil, e
	}
	rows, ok := arr(cap["channels"])
	if !ok || len(rows) != 2 {
		return nil, errors.New("channels")
	}
	channelIDs := []string{"fixture-primary", "fixture-mirror"}
	operatorIDs := []string{"fixture-primary-operator", "fixture-mirror-operator"}
	channelKeys := map[string]ed25519.PublicKey{}
	channelDER := map[string][]byte{}
	channelSpecs := []any{}
	for i, row := range rows {
		m, ok := obj(row)
		if !ok {
			return nil, errors.New("channel")
		}
		cid, _ := fieldString(m, "channelId")
		oid, _ := fieldString(m, "operatorId")
		if cid != channelIDs[i] || oid != operatorIDs[i] {
			return nil, errors.New("channel identity")
		}
		key, der, e := readKey(root, m, []string{"channelId", "operatorId", "path", "spki"})
		if e != nil {
			return nil, e
		}
		channelKeys[cid] = key
		channelDER[cid] = der
		channelSpecs = append(channelSpecs, map[string]any{"channelId": cid, "operatorId": oid, "spki": identity(der)})
	}
	policyExpected := map[string]any{"action": "register-content-control-policy", "antiRollbackPolicy": map[string]any{"floorMode": "revocation-sequence-inclusive", "rejectedObservationDoesNotAdvanceHistory": true, "revokedDigestRemainsRejectedAboveFloor": true}, "channels": channelSpecs, "claimBoundary": map[string]any{"doesNotImply": claimBoundary}, "contentControlRootSpki": identity(rootDER), "policyId": policyID, "policySequence": 30, "revocationAuthority": map[string]any{"id": rid, "spki": identity(revDER)}, "sourceAuthority": source, "standard": "EIGIIB-P1-A13-POLICY-1.0"}
	policyEnv, e := signed(cap["policy"], policyExpected, policyType, rootKey, rootDER, verify)
	if e != nil {
		return nil, e
	}
	policyIdentity := identity(policyEnv)
	revExpected := map[string]any{"action": "revoke-content", "content": content, "effectiveTimeUnix": 1785607200, "policyEnvelope": policyIdentity, "reasonCode": "security-withdrawal", "replacement": nil, "revocationId": revocationID, "revocationSequence": 31, "sourceAuthority": source, "standard": "EIGIIB-P1-A13-REVOCATION-1.0"}
	revEnv, e := signed(cap["revocation"], revExpected, revocationType, revKey, revDER, verify)
	if e != nil {
		return nil, e
	}
	revIdentity := identity(revEnv)
	withdrawals, ok := arr(cap["withdrawals"])
	if !ok || len(withdrawals) != 2 {
		return nil, errors.New("withdrawals")
	}
	accepted := []any{"policy-sequence-30", "revocation-sequence-31"}
	withdrawn := []any{}
	for i, row := range withdrawals {
		cid := channelIDs[i]
		seq := 32 + i
		expected := map[string]any{"action": "withdraw-distribution", "availabilityState": "withdrawn-from-registered-channel", "channel": map[string]any{"channelId": cid, "operatorId": operatorIDs[i]}, "content": content, "observedAtUnix": 1785609000 + i*60, "policyEnvelope": policyIdentity, "revocationEnvelope": revIdentity, "standard": "EIGIIB-P1-A13-WITHDRAWAL-1.0", "withdrawalId": "eigiib-p1-a13-withdrawal-" + cid, "withdrawalSequence": seq}
		if _, e = signed(row, expected, withdrawalType, channelKeys[cid], channelDER[cid], verify); e != nil {
			return nil, e
		}
		accepted = append(accepted, fmt.Sprintf("%s-withdrawal-sequence-%d", cid, seq))
		withdrawn = append(withdrawn, cid)
	}
	replays, ok := arr(cap["replays"])
	if !ok || len(replays) != 3 {
		return nil, errors.New("replays")
	}
	ids := []string{"pre-revocation-sequence", "at-revocation-floor", "newer-sequence-same-content"}
	seqs := []int{30, 31, 34}
	cids := []string{"fixture-primary", "fixture-mirror", "fixture-primary"}
	decisions := []string{"rejected-below-revocation-floor", "rejected-revoked-content", "rejected-revoked-content"}
	replayResults := []any{}
	for i, row := range replays {
		m, ok := obj(row)
		if !ok || !requireKeys(m, "id", "observation", "expectedDecision") || m["id"] != ids[i] || m["expectedDecision"] != decisions[i] {
			return nil, errors.New("replay")
		}
		cid := cids[i]
		oi := 0
		if cid == "fixture-mirror" {
			oi = 1
		}
		expected := map[string]any{"action": "observe-distribution", "channel": map[string]any{"channelId": cid, "operatorId": operatorIDs[oi]}, "content": content, "distributionSequence": seqs[i], "observedAtUnix": 1785609600 + i*60, "policyEnvelope": policyIdentity, "standard": "EIGIIB-P1-A13-OBSERVATION-1.0"}
		if _, e = signed(m["observation"], expected, observationType, channelKeys[cid], channelDER[cid], verify); e != nil {
			return nil, e
		}
		replayResults = append(replayResults, map[string]any{"decision": decisions[i], "id": ids[i], "sequence": seqs[i]})
	}
	return map[string]any{"accepted_history": accepted, "anti_rollback_floor_sequence": 31, "anti_rollback_result": "conformant-for-revocation-floor-and-registered-channel-history-scope", "boundary": boundary, "claim_boundary": claimBoundary, "content_archive_sha256": archiveSHA, "content_revocation_result": "conformant-for-exact-release-content-scope", "distribution_withdrawal_result": "conformant-for-two-registered-fixture-channels-scope", "global_content_unavailability_result": "not-claimed", "overall_result": "conformant", "policy_envelope_sha256": sha(policyEnv), "profile": profile, "registered_channel_ids": []any{"fixture-primary", "fixture-mirror"}, "release_descriptor_sha256": releaseDescriptorSHA, "release_id": releaseID, "replay_results": replayResults, "revocation_envelope_sha256": sha(revEnv), "revocation_id": revocationID, "revocation_sequence": 31, "source_transparency_capsule_sha256": a12CapsuleSHA, "source_transparency_report_sha256": a12ReportSHA, "standard": standard, "tool": "eigiib-p1-a13-revocation-check", "tool_version": "0.1.0", "trusted_effective_time_unix": 1785603600, "vulnerability_remediation_result": "not-claimed", "withdrawn_channel_ids": withdrawn}, nil
}

func CanonicalResult(result map[string]any) ([]byte, error) { return canonicalJSON(result) }
