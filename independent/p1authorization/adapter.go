package p1authorization

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
)

const (
	Standard           = "EIGIIB-P1-A10-ROUTE-1.0"
	Route              = "independent-go-stdlib"
	profile            = "delegated-threshold-authorization-revocation-v1"
	policyType         = "application/vnd.eigiib.release-authorization-policy+json"
	approvalType       = "application/vnd.eigiib.release-approval+json"
	revocationType     = "application/vnd.eigiib.delegate-revocation+json"
	policyID           = "eigiib-p1-a10-release-policy-1"
	threshold          = 2
	revocationSequence = 11
)

type delegateKey struct {
	key  ed25519.PublicKey
	der  []byte
	spki Identity
}

func approvalSet(approvals []Approval, payload []byte, delegates map[string]delegateKey, evaluation int) ([]string, []string, error) {
	if len(approvals) != threshold {
		return nil, nil, errors.New("approval count")
	}
	seen := map[string]bool{}
	signers := []string{}
	active := []string{}
	for _, row := range approvals {
		d, ok := delegates[row.DelegateID]
		if !ok || seen[row.DelegateID] {
			return nil, nil, errors.New("approval delegate")
		}
		seen[row.DelegateID] = true
		raw, e := carrierBytes(row.Envelope)
		if e != nil {
			return nil, nil, e
		}
		if e = verifyCOSE(raw, payload, approvalType, d.key, d.der); e != nil {
			return nil, nil, e
		}
		signers = append(signers, row.DelegateID)
		if !(row.DelegateID == "delegate-b" && evaluation >= revocationSequence) {
			active = append(active, row.DelegateID)
		}
	}
	return signers, active, nil
}

func Evaluate(root, capsulePath string) (Result, error) {
	var result Result
	capsuleRaw, e := os.ReadFile(capsulePath)
	if e != nil {
		return result, e
	}
	var capsule Capsule
	if e = decodeStruct(capsuleRaw, &capsule); e != nil {
		return result, e
	}
	if capsule.Standard != "EIGIIB-P1-A10-1.0" || capsule.Profile != profile {
		return result, errors.New("capsule constants")
	}
	releaseRaw, _, e := safeRead(root, capsule.SourceRelease.Path)
	if e != nil {
		return result, e
	}
	var release map[string]any
	if e = decodeStruct(releaseRaw, &release); e != nil {
		return result, e
	}
	releaseID, ok := release["releaseId"].(string)
	if !ok || releaseID == "" || capsule.SourceRelease.ReleaseID != releaseID || !sameIdentity(capsule.SourceRelease.Identity, releaseRaw) {
		return result, errors.New("release identity")
	}
	_, releaseDER, _, e := readKey(root, capsule.SourceReleaseSigner, false)
	if e != nil {
		return result, e
	}
	rootKey, rootDER, _, e := readKey(root, capsule.TrustRoot, false)
	if e != nil {
		return result, e
	}
	if len(capsule.Delegates) != 3 {
		return result, errors.New("delegates")
	}
	delegates := map[string]delegateKey{}
	order := []string{}
	for _, row := range capsule.Delegates {
		k, der, _, e := readKey(root, row, true)
		if e != nil {
			return result, e
		}
		if _, dup := delegates[row.ID]; dup {
			return result, errors.New("duplicate delegate")
		}
		delegates[row.ID] = delegateKey{k, der, row.SPKI}
		order = append(order, row.ID)
	}
	if fmt.Sprint(order) != "[delegate-a delegate-b delegate-c]" {
		return result, errors.New("delegate order")
	}
	delegateRows := []any{}
	for _, id := range order {
		delegateRows = append(delegateRows, map[string]any{"id": id, "spki": delegates[id].spki})
	}
	expectedPolicy := map[string]any{
		"action":        "delegate-release-authorization",
		"claimBoundary": map[string]any{"doesNotImply": []any{"supplied-root-does-not-prove-real-world-identity", "sequence-does-not-imply-trusted-time", "delegate-revocation-does-not-imply-content-revocation", "fixture-authorization-does-not-imply-production-governance"}},
		"delegates":     delegateRows, "policyId": policyID, "policySequence": 1,
		"releaseScope":            map[string]any{"releaseDescriptor": identity(releaseRaw), "releaseId": releaseID, "releaseSignerSpki": capsule.SourceReleaseSigner.SPKI},
		"revocationAuthoritySpki": capsule.TrustRoot.SPKI, "role": "release-approver", "standard": "EIGIIB-P1-A10-POLICY-1.0", "threshold": threshold,
	}
	policyPayload, e := carrierBytes(capsule.Policy.Payload)
	if e != nil {
		return result, e
	}
	if e = expectCanonical(policyPayload, expectedPolicy, "policy"); e != nil {
		return result, e
	}
	policyEnvelope, e := carrierBytes(capsule.Policy.Envelope)
	if e != nil {
		return result, e
	}
	if e = verifyCOSE(policyEnvelope, policyPayload, policyType, rootKey, rootDER); e != nil {
		return result, e
	}
	authExpected := func(seq int) map[string]any {
		return map[string]any{"action": "authorize-release", "authorizationSequence": seq, "policyId": policyID, "policySequence": 1, "releaseDescriptor": identity(releaseRaw), "releaseId": releaseID, "releaseSignerSpki": capsule.SourceReleaseSigner.SPKI, "standard": "EIGIIB-P1-A10-AUTHORIZATION-1.0"}
	}
	if capsule.InitialAuthorization.EvaluationSequence != 10 {
		return result, errors.New("initial sequence")
	}
	initialPayload, e := carrierBytes(capsule.InitialAuthorization.Payload)
	if e != nil {
		return result, e
	}
	if e = expectCanonical(initialPayload, authExpected(10), "initial authorization"); e != nil {
		return result, e
	}
	revExpected := map[string]any{"action": "revoke-delegate-authorization", "claimBoundary": map[string]any{"doesNotImply": []any{"content-revocation", "distribution-withdrawal", "trusted-effective-time"}}, "policyId": policyID, "policySequence": 1, "revocationSequence": 11, "scope": "evaluations-at-or-after-revocation-sequence", "standard": "EIGIIB-P1-A10-REVOCATION-1.0", "subjectDelegateId": "delegate-b", "subjectSpki": capsule.Delegates[1].SPKI}
	revPayload, e := carrierBytes(capsule.Revocation.Payload)
	if e != nil {
		return result, e
	}
	if e = expectCanonical(revPayload, revExpected, "revocation"); e != nil {
		return result, e
	}
	revEnvelope, e := carrierBytes(capsule.Revocation.Envelope)
	if e != nil {
		return result, e
	}
	if e = verifyCOSE(revEnvelope, revPayload, revocationType, rootKey, rootDER); e != nil {
		return result, e
	}
	initialSigners, initialActive, e := approvalSet(capsule.InitialAuthorization.Approvals, initialPayload, delegates, 10)
	if e != nil || len(initialActive) < threshold {
		return result, errors.New("initial threshold")
	}
	if capsule.StaleReplay.EvaluationSequence != 12 || capsule.StaleReplay.Expected != "rejected-revoked-threshold" || capsule.StaleReplay.UsesAuthorizationSequence != 10 {
		return result, errors.New("stale carrier")
	}
	_, staleActive, e := approvalSet(capsule.InitialAuthorization.Approvals, initialPayload, delegates, 12)
	if e != nil || len(staleActive) >= threshold {
		return result, errors.New("stale replay")
	}
	if capsule.RecoveredAuthorization.EvaluationSequence != 12 {
		return result, errors.New("recovered sequence")
	}
	recoveredPayload, e := carrierBytes(capsule.RecoveredAuthorization.Payload)
	if e != nil {
		return result, e
	}
	if e = expectCanonical(recoveredPayload, authExpected(12), "recovered authorization"); e != nil {
		return result, e
	}
	recoveredSigners, recoveredActive, e := approvalSet(capsule.RecoveredAuthorization.Approvals, recoveredPayload, delegates, 12)
	if e != nil || len(recoveredActive) < threshold || fmt.Sprint(recoveredSigners) != "[delegate-a delegate-c]" {
		return result, errors.New("recovered threshold")
	}
	if len(capsule.ClaimBoundary.DoesNotImply) < 8 {
		return result, errors.New("claim boundary")
	}
	_ = bytes.Equal
	result = Result{Standard: Standard, Route: Route, ReleaseID: releaseID, ReleaseDescriptorSHA256: identity(releaseRaw).Digest, ReleaseSignerSPKISHA256: identity(releaseDER).Digest, TrustRootSPKISHA256: identity(rootDER).Digest, PolicyEnvelopeSHA256: identity(policyEnvelope).Digest, Threshold: threshold, DelegateCount: 3, InitialApprovalIDs: initialSigners, RevokedDelegateID: "delegate-b", RevocationSequence: 11, RecoveredApprovalIDs: recoveredSigners, TrustedReleaseSignerResult: "conformant-for-supplied-root-policy-scope", AuthorizedReleaseSignerResult: "conformant-for-exact-release-descriptor-scope", Accepted: true, Boundary: "recovered-threshold-authorization"}
	return result, nil
}
