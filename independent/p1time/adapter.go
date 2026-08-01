package p1time

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"
)

const (
	Route           = "independent-go-stdlib"
	Standard        = "EIGIIB-P1-A11-ROUTE-1.0"
	profile         = "trusted-timestamp-window-rollback-expiry-v1"
	policyType      = "application/vnd.eigiib.trusted-time-policy+json"
	observationType = "application/vnd.eigiib.trusted-time-observation+json"
	policyID        = "eigiib-p1-a11-time-policy-1"
	authorityID     = "eigiib-p1-a11-tsa-1"
	notBefore       = int64(1785600000)
	notAfter        = int64(1785686400)
	boundary        = "trusted-time-window-rollback-expiry-closure"
)

var expectedObservations = []struct {
	ID, RFC3339, Decision string
	Sequence              int
	Unix                  int64
}{
	{"before-window", "2026-08-01T15:59:59Z", "rejected-not-yet-valid", 100, 1785599999},
	{"valid-window", "2026-08-01T17:00:00Z", "conformant", 101, 1785603600},
	{"clock-rollback", "2026-08-01T16:30:00Z", "rejected-clock-rollback", 102, 1785601800},
	{"expired-window", "2026-08-02T16:00:01Z", "rejected-expired", 103, 1785686401},
}

type a10Report struct {
	OverallResult                string `json:"overall_result"`
	RecoveredAuthorizationSHA256 string `json:"recovered_authorization_sha256"`
	ReleaseDescriptorSHA256      string `json:"release_descriptor_sha256"`
	ReleaseID                    string `json:"release_id"`
}

type a10Capsule struct {
	RecoveredAuthorization struct {
		Payload DataCarrier `json:"payload"`
	} `json:"recoveredAuthorization"`
}

func sourceMap(source SourceAuthorization) map[string]any {
	return map[string]any{
		"authorizationCapsule":          map[string]any{"identity": source.AuthorizationCapsule.Identity, "path": source.AuthorizationCapsule.Path},
		"authorizationReport":           map[string]any{"identity": source.AuthorizationReport.Identity, "path": source.AuthorizationReport.Path},
		"recoveredAuthorizationPayload": source.RecoveredAuthorizationPayload,
		"releaseDescriptor":             source.ReleaseDescriptor,
		"releaseId":                     source.ReleaseID,
	}
}

func Evaluate(root, capsulePath string) (Result, error) {
	var result Result
	capsuleRaw, err := os.ReadFile(capsulePath)
	if err != nil {
		return result, err
	}
	var capsule Capsule
	if err = decodeStruct(capsuleRaw, &capsule); err != nil {
		return result, err
	}
	if capsule.Standard != "EIGIIB-P1-A11-1.0" || capsule.Profile != profile {
		return result, errors.New("capsule constants")
	}

	reportRaw, _, err := safeRead(root, capsule.SourceAuthorization.AuthorizationReport.Path)
	if err != nil || !sameIdentity(capsule.SourceAuthorization.AuthorizationReport.Identity, reportRaw) {
		return result, errors.New("authorization report identity")
	}
	var report a10Report
	if _, err = strictJSON(reportRaw); err != nil {
		return result, errors.New("authorization report")
	}
	if err = json.Unmarshal(reportRaw, &report); err != nil || report.OverallResult != "conformant" {
		return result, errors.New("authorization report")
	}
	a10Raw, _, err := safeRead(root, capsule.SourceAuthorization.AuthorizationCapsule.Path)
	if err != nil || !sameIdentity(capsule.SourceAuthorization.AuthorizationCapsule.Identity, a10Raw) {
		return result, errors.New("authorization capsule identity")
	}
	var previous a10Capsule
	if _, err = strictJSON(a10Raw); err != nil {
		return result, err
	}
	if err = json.Unmarshal(a10Raw, &previous); err != nil {
		return result, err
	}
	recoveredRaw, err := carrierBytes(previous.RecoveredAuthorization.Payload)
	if err != nil || !sameIdentity(capsule.SourceAuthorization.RecoveredAuthorizationPayload, recoveredRaw) || identity(recoveredRaw).Digest != report.RecoveredAuthorizationSHA256 {
		return result, errors.New("recovered authorization binding")
	}
	expectedSource := SourceAuthorization{
		AuthorizationCapsule:          FileCarrier{Identity: identity(a10Raw), Path: "tests/fixtures/p1-a10/capsule.json"},
		AuthorizationReport:           FileCarrier{Identity: identity(reportRaw), Path: "tests/fixtures/p1-a10/expected-report.json"},
		RecoveredAuthorizationPayload: identity(recoveredRaw),
		ReleaseDescriptor:             Identity{Algorithm: "sha256", Bytes: 1278, Digest: report.ReleaseDescriptorSHA256},
		ReleaseID:                     report.ReleaseID,
	}
	if !reflect.DeepEqual(capsule.SourceAuthorization, expectedSource) {
		return result, errors.New("source authorization")
	}

	rootKey, rootDER, _, err := readKey(root, capsule.TimeTrustRoot, false)
	if err != nil {
		return result, err
	}
	tsaKey, tsaDER, _, err := readKey(root, capsule.TimestampAuthority, true)
	if err != nil || capsule.TimestampAuthority.ID != authorityID {
		return result, errors.New("timestamp authority")
	}

	expectedPolicy := map[string]any{
		"action":        "delegate-trusted-timestamp-authority",
		"authority":     map[string]any{"id": authorityID, "spki": capsule.TimestampAuthority.SPKI},
		"claimBoundary": map[string]any{"doesNotImply": []string{"supplied-time-root-does-not-prove-real-world-identity", "signed-time-does-not-prove-secure-clock-hardware", "fixture-window-does-not-establish-legal-effective-time", "trusted-time-does-not-imply-content-revocation"}},
		"clockPolicy":   map[string]any{"observationSequenceStrictlyIncreasing": true, "rejectTimestampRegression": true, "rejectedObservationDoesNotAdvanceAcceptedClock": true},
		"policyId":      policyID, "policySequence": 1,
		"sourceAuthorization": sourceMap(expectedSource),
		"standard":            "EIGIIB-P1-A11-TIME-POLICY-1.0",
		"validityWindow":      map[string]any{"boundaryPolicy": "inclusive", "notAfterRfc3339": "2026-08-02T16:00:00Z", "notAfterUnix": notAfter, "notBeforeRfc3339": "2026-08-01T16:00:00Z", "notBeforeUnix": notBefore},
	}
	policyPayload, err := carrierBytes(capsule.Policy.Payload)
	if err != nil {
		return result, err
	}
	if err = expectCanonical(policyPayload, expectedPolicy, "time policy"); err != nil {
		return result, err
	}
	policyEnvelope, err := carrierBytes(capsule.Policy.Envelope)
	if err != nil {
		return result, err
	}
	if err = verifyCOSE(policyEnvelope, policyPayload, policyType, rootKey, rootDER); err != nil {
		return result, err
	}

	if len(capsule.Observations) != len(expectedObservations) {
		return result, errors.New("observation count")
	}
	subject := map[string]any{"authorizationReport": identity(reportRaw), "recoveredAuthorizationPayload": identity(recoveredRaw), "releaseDescriptor": expectedSource.ReleaseDescriptor, "releaseId": report.ReleaseID}
	lastSequence := -1
	lastAccepted := int64(-1)
	accepted := []string{}
	for index, spec := range expectedObservations {
		row := capsule.Observations[index]
		if row.ID != spec.ID || row.ExpectedDecision != spec.Decision {
			return result, errors.New("observation identity")
		}
		payload, err := carrierBytes(row.Payload)
		if err != nil {
			return result, err
		}
		expectedPayload := map[string]any{
			"authorityId": authorityID, "observationId": spec.ID, "observationSequence": spec.Sequence,
			"policyId": policyID, "policySequence": 1, "purpose": "evaluate-release-authorization-validity",
			"standard": "EIGIIB-P1-A11-TIME-OBSERVATION-1.0", "subject": subject,
			"timestampRfc3339": spec.RFC3339, "timestampUnix": spec.Unix,
		}
		if err = expectCanonical(payload, expectedPayload, "observation"); err != nil {
			return result, err
		}
		parsed, err := time.Parse(time.RFC3339, spec.RFC3339)
		if err != nil || parsed.Unix() != spec.Unix {
			return result, errors.New("timestamp representation")
		}
		envelope, err := carrierBytes(row.Envelope)
		if err != nil {
			return result, err
		}
		if err = verifyCOSE(envelope, payload, observationType, tsaKey, tsaDER); err != nil {
			return result, err
		}
		if spec.Sequence <= lastSequence {
			return result, errors.New("observation sequence rollback")
		}
		lastSequence = spec.Sequence
		decision := "conformant"
		if spec.Unix < notBefore {
			decision = "rejected-not-yet-valid"
		} else if spec.Unix > notAfter {
			decision = "rejected-expired"
		} else if lastAccepted >= 0 && spec.Unix < lastAccepted {
			decision = "rejected-clock-rollback"
		} else {
			lastAccepted = spec.Unix
			accepted = append(accepted, spec.ID)
		}
		if decision != spec.Decision {
			return result, fmt.Errorf("observation decision %s", spec.ID)
		}
	}
	claim := []string{"time-root-fixture-does-not-prove-real-world-operator-identity", "timestamp-signature-does-not-prove-clock-hardware-integrity", "validity-window-does-not-imply-legal-or-business-effective-time", "time-validation-does-not-imply-transparency-log-trust", "time-validation-does-not-imply-global-append-only-consistency", "time-validation-does-not-imply-content-revocation-or-withdrawal", "p1-a11-does-not-imply-production-release-governance"}
	if !reflect.DeepEqual(capsule.ClaimBoundary.DoesNotImply, claim) {
		return result, errors.New("claim boundary")
	}

	result = Result{
		Standard: Standard, Route: Route, ReleaseID: report.ReleaseID,
		AuthorizationReportSHA256: identity(reportRaw).Digest, RecoveredAuthorizationSHA256: identity(recoveredRaw).Digest,
		TimeTrustRootSPKISHA256: identity(rootDER).Digest, TimestampAuthorityID: authorityID,
		TimestampAuthoritySPKISHA256: identity(tsaDER).Digest, TimePolicyEnvelopeSHA256: identity(policyEnvelope).Digest,
		NotBeforeUnix: notBefore, NotAfterUnix: notAfter, AcceptedObservationIDs: accepted,
		LastAcceptedTimestampUnix: lastAccepted, NotYetValidResult: "rejected-as-required", ValidWindowResult: "conformant",
		ClockRollbackResult: "rejected-as-required", ExpiryResult: "rejected-as-required",
		TrustedTimestampAuthorityResult: "conformant-for-supplied-time-root-delegation-scope",
		TrustedEffectiveTimeResult:      "conformant-for-signed-observation-and-closed-window-scope",
		Accepted:                        true, Boundary: boundary,
	}
	return result, nil
}
