#!/usr/bin/env python3
"""Fail-closed structural and evidence verifier for EIGIIB M0-A12."""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eigiib_m0_a12_canonical import digest_document, load_json
from eigiib_m0_a12_signature import DEFAULT_NAMESPACE, SignatureError, verify_file

STANDARD = "EIGIIB-M0-A12-1.0"
REPORT_STANDARD = "EIGIIB-M0-A12-REPORT-1.0"
M0_A11_HEAD = "148e3e9d06ce791b90e2816d77f5045ebeac0793"
M0_A10_HEAD = "2891265f04a5d9a4d69c134fa48881b0ed93fe13"
BUNDLE_SHA256 = "96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
BUNDLE_BYTES = 985664
AUTHORITY_PATH = "conformance/m0-a12-external-activation.json"
PROFILES_PATH = "conformance/m0-a12-provider-profiles.json"
PROTOCOL_PATH = "conformance/m0-a12-htnt-decision-protocol.json"
LEDGER_PATH = "conformance/m0-a12-evidence-ledger.json"
FREEZE_PATH = "conformance/m0-a12-authority-freeze.json"
M0_A11_PATH = "conformance/m0-a11-external-evidence-preparation.json"
EVIDENCE_ROOT = "evidence/m0-a12"
DOMAINS = [
    "github-existing-publication-domain",
    "external-preservation-primary",
    "external-preservation-secondary",
    "independent-observer-primary",
]
EXTERNAL_DOMAINS = DOMAINS[1:]
CHANNELS = ["immutable-channel-primary", "immutable-channel-secondary"]
DIMENSIONS = [
    "provider-operator",
    "tenant-account",
    "identity-root",
    "privileged-administrator",
    "billing-authority",
    "credential-store",
    "execution-plane",
    "region-or-failure-domain",
    "audit-log-custody",
]
EXPECTED_EVIDENCE = [
    "control-domains/external-preservation-primary.json",
    "control-domains/external-preservation-primary.json.sig",
    "control-domains/external-preservation-secondary.json",
    "control-domains/external-preservation-secondary.json.sig",
    "control-domains/independent-observer-primary.json",
    "control-domains/independent-observer-primary.json.sig",
    "keys/allowed_signers.json",
    "channels/immutable-channel-primary.json",
    "channels/immutable-channel-secondary.json",
    "diversity-matrix.json",
    "campaign-anchor.json",
    "observations/000001.json",
    "observations/000001.json.sig",
]


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add(findings: list[str], code: str, condition: bool) -> None:
    if condition:
        findings.append(code)


def verify_digest(findings: list[str], code: str, document: dict[str, Any], field: str) -> None:
    actual = document.get(field)
    try:
        expected = digest_document(document, field)
    except Exception:
        findings.append(code + ".CANONICALIZATION")
        return
    if actual != expected:
        findings.append(code + ".DIGEST")


def load_required(root: Path, rel: str, findings: list[str]) -> dict[str, Any]:
    try:
        return load_json(root / rel)
    except Exception as exc:
        findings.append(f"M0A12.JSON:{rel}:{type(exc).__name__}")
        return {}


def evaluate_baseline(root: Path, findings: list[str]) -> dict[str, Any]:
    authority = load_required(root, AUTHORITY_PATH, findings)
    profiles = load_required(root, PROFILES_PATH, findings)
    protocol = load_required(root, PROTOCOL_PATH, findings)
    ledger = load_required(root, LEDGER_PATH, findings)
    m0a11 = load_required(root, M0_A11_PATH, findings)

    add(findings, "M0A12.AUTHORITY.STANDARD", authority.get("standard") != STANDARD)
    add(findings, "M0A12.AUTHORITY.STATUS", authority.get("status") != "activation-harness-established-external-evidence-pending")
    source = authority.get("source", {})
    add(findings, "M0A12.SOURCE.M0A11", source.get("m0A11Head") != M0_A11_HEAD)
    add(findings, "M0A12.SOURCE.M0A10", source.get("m0A10Head") != M0_A10_HEAD)
    bundle = source.get("stableBundle", {})
    add(findings, "M0A12.SOURCE.BUNDLE_SHA", bundle.get("sha256") != BUNDLE_SHA256)
    add(findings, "M0A12.SOURCE.BUNDLE_BYTES", bundle.get("bytes") != BUNDLE_BYTES)
    add(findings, "M0A12.SOURCE.M0A11_AUTHORITY", m0a11.get("standard") != "EIGIIB-M0-A11-1.0")
    add(findings, "M0A12.SOURCE.M0A11_STATUS", m0a11.get("status") != "external-evidence-acquisition-prepared-not-activated")
    entry = m0a11.get("entryGates", {}).get("m0A12", {})
    add(findings, "M0A12.SOURCE.ENTRY_GATE", entry.get("decision") != "ready-for-external-activation-only")

    typed = authority.get("typedDecisionProtocol", {})
    add(findings, "M0A12.HTNT.CARRIER", typed.get("carrier") != "S4-internal-external-square")
    add(findings, "M0A12.HTNT.CURRENT", typed.get("currentLabel") != "NF" or typed.get("currentCoordinates") != [1, 0])
    add(findings, "M0A12.HTNT.CLOSURE", typed.get("closureLabel") != "T")
    add(findings, "M0A12.HTNT.OFF_DIAGONAL", typed.get("offDiagonalPromotion") != "forbidden")

    add(findings, "M0A12.PROFILES.STANDARD", profiles.get("standard") != "EIGIIB-M0-A12-PROVIDER-PROFILES-1.0")
    profile_docs = profiles.get("profiles", [])
    profile_ids = [p.get("id") for p in profile_docs if isinstance(p, dict)]
    add(findings, "M0A12.PROFILES.SET", profile_ids != [
        "aws-s3-object-lock-compliance",
        "gcp-cloud-storage-bucket-lock",
        "external-gitlab-scheduled-runner",
    ])
    for profile in profile_docs:
        pid = profile.get("id", "unknown")
        add(findings, f"M0A12.PROFILE.PREMATURE_RESOURCE:{pid}", profile.get("resourceBindingState") != "unbound")
        add(findings, f"M0A12.PROFILE.PREMATURE_CREDENTIAL:{pid}", profile.get("credentialBindingState") != "unbound")
    boundary = profiles.get("selectionBoundary", {})
    for key in ["sameProviderOperatorForBothCustodians","sameTenantAccount","sameIdentityRoot","sameCredentialStore","sameExecutionPlaneForObserver"]:
        add(findings, f"M0A12.PROFILE.BOUNDARY:{key}", boundary.get(key) != "denied")
    add(findings, "M0A12.PROFILE.UNKNOWN", boundary.get("unknownDimension") != "not-independent")

    add(findings, "M0A12.PROTOCOL.STANDARD", protocol.get("standard") != "EIGIIB-M0-A12-HTNT-DECISION-PROTOCOL-1.0")
    add(findings, "M0A12.PROTOCOL.CONTEXT", protocol.get("fixedContext") is not True)
    carrier = protocol.get("carrier", {})
    add(findings, "M0A12.PROTOCOL.LABELS", carrier.get("labels") != {"F":[0,0],"NF":[1,0],"NT":[0,1],"T":[1,1]})
    add(findings, "M0A12.PROTOCOL.PROMOTION", protocol.get("binaryPromotionRule", {}).get("offDiagonal") != "suspended")
    obligations = protocol.get("transitionMeasure", {}).get("obligations", [])
    add(findings, "M0A12.PROTOCOL.MEASURE", len(obligations) != 8 or len(set(obligations)) != 8)

    add(findings, "M0A12.LEDGER.STANDARD", ledger.get("standard") != "EIGIIB-M0-A12-EVIDENCE-LEDGER-1.0")
    add(findings, "M0A12.LEDGER.STATUS", ledger.get("status") != "external-evidence-pending")
    add(findings, "M0A12.LEDGER.SOURCE", ledger.get("sourceHead") != M0_A11_HEAD)
    add(findings, "M0A12.LEDGER.PREMATURE", ledger.get("entries") != [] or ledger.get("activationDecision") != "not-activated" or ledger.get("observationCount") != 0)

    claims = authority.get("claimBoundary", {})
    for key in ["providerProfileSelectionIsNotProviderBinding","adapterAvailabilityIsNotChannelProvisioning","syntheticSignatureVectorIsNotExternalAttestation","firstObservationIsNotLongHorizonEvidence"]:
        add(findings, f"M0A12.BOUNDARY:{key}", claims.get(key) is not True)
    add(findings, "M0A12.BOUNDARY.UNKNOWN", claims.get("unknownExternalFacts") != "deny")
    add(findings, "M0A12.BOUNDARY.E17", claims.get("e17Decision") != "not-ready-for-adoption")

    return {
        "authority": authority,
        "profiles": profiles,
        "protocol": protocol,
        "ledger": ledger,
    }


def verify_freeze(root: Path, findings: list[str]) -> int:
    freeze = load_required(root, FREEZE_PATH, findings)
    add(findings, "M0A12.FREEZE.STANDARD", freeze.get("standard") != "EIGIIB-M0-A12-AUTHORITY-FREEZE-1.0")
    add(findings, "M0A12.FREEZE.SOURCE", freeze.get("sourceHead") != M0_A11_HEAD)
    authorities = freeze.get("authorities", [])
    add(findings, "M0A12.FREEZE.COUNT", freeze.get("authorityCount") != len(authorities))
    add(findings, "M0A12.FREEZE.EXCLUSION", freeze.get("excludedPath") != FREEZE_PATH)
    seen: set[str] = set()
    for item in authorities:
        rel = item.get("path")
        if not rel or rel in seen or rel == FREEZE_PATH:
            findings.append("M0A12.FREEZE.PATH_SET")
            continue
        seen.add(rel)
        path = root / rel
        if not path.is_file():
            findings.append(f"M0A12.FREEZE.MISSING:{rel}")
            continue
        if path.stat().st_size != item.get("bytes"):
            findings.append(f"M0A12.FREEZE.BYTES:{rel}")
        if sha256(path) != item.get("sha256"):
            findings.append(f"M0A12.FREEZE.SHA256:{rel}")
    return len(authorities)


def verify_signature_for(
    evidence_root: Path,
    relative_payload: str,
    identity: str,
    findings: list[str],
    code: str,
) -> None:
    payload = evidence_root / relative_payload
    signature = Path(str(payload) + ".sig")
    allowed = evidence_root / "keys/allowed_signers.json"
    try:
        verify_file(payload, signature, allowed, identity, DEFAULT_NAMESPACE)
    except (OSError, SignatureError) as exc:
        findings.append(f"{code}.SIGNATURE:{type(exc).__name__}")


def evaluate_evidence(root: Path, findings: list[str]) -> dict[str, Any]:
    evidence_root = root / EVIDENCE_ROOT
    if not evidence_root.exists():
        return {"present": False, "complete": False, "observationCount": 0}

    for rel in EXPECTED_EVIDENCE:
        if not (evidence_root / rel).is_file():
            findings.append(f"M0A12.EVIDENCE.MISSING:{rel}")
    if any(code.startswith("M0A12.EVIDENCE.MISSING") for code in findings):
        return {"present": True, "complete": False, "observationCount": 0}

    attestations: dict[str, dict[str, Any]] = {}
    for domain in EXTERNAL_DOMAINS:
        rel = f"control-domains/{domain}.json"
        doc = load_required(evidence_root, rel, findings)
        attestations[domain] = doc
        add(findings, f"M0A12.DOMAIN.STANDARD:{domain}", doc.get("standard") != "EIGIIB-M0-A12-CONTROL-DOMAIN-ATTESTATION-1.0")
        add(findings, f"M0A12.DOMAIN.ID:{domain}", doc.get("domainId") != domain)
        expected_role = "independent-observer" if domain == "independent-observer-primary" else "preservation-custodian"
        add(findings, f"M0A12.DOMAIN.ROLE:{domain}", doc.get("role") != expected_role)
        for field in ["providerOperator","service","tenantAccountId","identityRoot","billingAuthority","credentialStore","executionPlane","auditLogCustody","signerKeyId"]:
            add(findings, f"M0A12.DOMAIN.FIELD:{domain}:{field}", not isinstance(doc.get(field), str) or not doc.get(field))
        admins = doc.get("privilegedAdministratorSet", [])
        regions = doc.get("regionOrFailureDomain", [])
        refs = doc.get("evidenceRefs", [])
        add(findings, f"M0A12.DOMAIN.ADMINS:{domain}", not admins or len(set(admins)) != len(admins))
        add(findings, f"M0A12.DOMAIN.REGIONS:{domain}", not regions or len(set(regions)) != len(regions))
        add(findings, f"M0A12.DOMAIN.REFS:{domain}", not refs or len(set(refs)) != len(refs))
        add(findings, f"M0A12.DOMAIN.BOUNDARY:{domain}", doc.get("claimBoundary") != "bounded-point-in-time-control-domain-attestation")
        try:
            parse_time(doc.get("issuedAt"))
        except Exception:
            findings.append(f"M0A12.DOMAIN.TIME:{domain}")
        verify_digest(findings, f"M0A12.DOMAIN:{domain}", doc, "payloadDigest")
        verify_signature_for(evidence_root, rel, domain, findings, f"M0A12.DOMAIN:{domain}")

    for left, right in itertools.combinations(EXTERNAL_DOMAINS, 2):
        left_doc, right_doc = attestations[left], attestations[right]
        scalar_fields = [
            "providerOperator","tenantAccountId","identityRoot","billingAuthority",
            "credentialStore","executionPlane","auditLogCustody",
        ]
        for field in scalar_fields:
            if left_doc.get(field) == right_doc.get(field):
                findings.append(f"M0A12.DOMAIN.SHARED:{left}:{right}:{field}")
        if set(left_doc.get("privilegedAdministratorSet", [])) & set(right_doc.get("privilegedAdministratorSet", [])):
            findings.append(f"M0A12.DOMAIN.SHARED:{left}:{right}:privilegedAdministratorSet")

    channel_docs: dict[str, dict[str, Any]] = {}
    expected_profiles = {
        "immutable-channel-primary": ("external-preservation-primary", "aws-s3-object-lock-compliance", "AWS-COMPLIANCE"),
        "immutable-channel-secondary": ("external-preservation-secondary", "gcp-cloud-storage-bucket-lock", "GCS-LOCKED-BUCKET-RETENTION"),
    }
    for channel, (domain, profile, mode) in expected_profiles.items():
        rel = f"channels/{channel}.json"
        doc = load_required(evidence_root, rel, findings)
        channel_docs[channel] = doc
        add(findings, f"M0A12.CHANNEL.STANDARD:{channel}", doc.get("standard") != "EIGIIB-M0-A12-CHANNEL-EVIDENCE-1.0")
        add(findings, f"M0A12.CHANNEL.ID:{channel}", doc.get("channelId") != channel)
        add(findings, f"M0A12.CHANNEL.DOMAIN:{channel}", doc.get("controlDomainId") != domain)
        add(findings, f"M0A12.CHANNEL.PROFILE:{channel}", doc.get("providerProfile") != profile)
        for field in ["providerResourceId","endpoint","objectVersionId"]:
            add(findings, f"M0A12.CHANNEL.FIELD:{channel}:{field}", not isinstance(doc.get(field), str) or not doc.get(field))
        artifact = doc.get("artifact", {})
        add(findings, f"M0A12.CHANNEL.ARTIFACT:{channel}", artifact.get("sha256") != BUNDLE_SHA256 or artifact.get("bytes") != BUNDLE_BYTES)
        retention = doc.get("retention", {})
        add(findings, f"M0A12.CHANNEL.RETENTION.MODE:{channel}", retention.get("mode") != mode)
        add(findings, f"M0A12.CHANNEL.RETENTION.STATE:{channel}", retention.get("policyState") != "applied-and-readback-verified")
        try:
            lock_at = parse_time(retention.get("lockEffectiveAt"))
            retain_until = parse_time(retention.get("retainUntil"))
            captured = parse_time(doc.get("capturedAt"))
            minimum = int(retention.get("minimumWindowSeconds"))
            if minimum < 86400 or retain_until.timestamp() - lock_at.timestamp() < minimum or captured < lock_at:
                findings.append(f"M0A12.CHANNEL.RETENTION.WINDOW:{channel}")
        except Exception:
            findings.append(f"M0A12.CHANNEL.RETENTION.TIME:{channel}")
        denials = doc.get("deleteDenials", [])
        classes = {d.get("principalClass") for d in denials if isinstance(d, dict)}
        add(findings, f"M0A12.CHANNEL.DELETE_DENIALS:{channel}", classes != {"authorized-deleter","privileged-administrator"})
        for denial in denials:
            if (
                denial.get("operation") != "delete-specific-object-version"
                or denial.get("result") != "denied"
                or denial.get("denialAttributedToRetention") is not True
                or denial.get("objectStillPresent") is not True
                or not denial.get("evidenceRef")
            ):
                findings.append(f"M0A12.CHANNEL.DELETE_DENIAL_DETAIL:{channel}")
        readback = doc.get("exactReadback", {})
        add(findings, f"M0A12.CHANNEL.READBACK:{channel}", readback.get("bytes") != BUNDLE_BYTES or readback.get("sha256") != BUNDLE_SHA256 or readback.get("readerDomainId") != "independent-observer-primary")
        verify_digest(findings, f"M0A12.CHANNEL:{channel}", doc, "payloadDigest")

    matrix = load_required(evidence_root, "diversity-matrix.json", findings)
    add(findings, "M0A12.DIVERSITY.STANDARD", matrix.get("standard") != "EIGIIB-M0-A12-DIVERSITY-MATRIX-1.0")
    add(findings, "M0A12.DIVERSITY.DOMAINS", matrix.get("domains") != DOMAINS)
    add(findings, "M0A12.DIVERSITY.DIMENSIONS", matrix.get("dimensions") != DIMENSIONS)
    comparisons = matrix.get("comparisons", [])
    expected_cells = {
        (left, right, dimension)
        for left, right in itertools.combinations(DOMAINS, 2)
        for dimension in DIMENSIONS
    }
    cells = {(c.get("left"), c.get("right"), c.get("dimension")) for c in comparisons if isinstance(c, dict)}
    add(findings, "M0A12.DIVERSITY.CELL_SET", cells != expected_cells or len(comparisons) != 54)
    for comparison in comparisons:
        if comparison.get("result") != "distinct" or not comparison.get("evidenceRefs"):
            findings.append("M0A12.DIVERSITY.NOT_DISTINCT")
            break
    add(findings, "M0A12.DIVERSITY.DECISION", matrix.get("decision") != "required-independence-established-for-point-in-time-activation")
    verify_digest(findings, "M0A12.DIVERSITY", matrix, "payloadDigest")

    anchor = load_required(evidence_root, "campaign-anchor.json", findings)
    add(findings, "M0A12.ANCHOR.STANDARD", anchor.get("standard") != "EIGIIB-M0-A12-CAMPAIGN-ANCHOR-1.0")
    add(findings, "M0A12.ANCHOR.CAMPAIGN", anchor.get("campaignId") != "eigiib-m0-a11-external-preservation-observation-v1")
    add(findings, "M0A12.ANCHOR.OBSERVER", anchor.get("observerDomainId") != "independent-observer-primary")
    add(findings, "M0A12.ANCHOR.CHANNELS", anchor.get("expectedChannelIds") != CHANNELS)
    versions = anchor.get("initialObjectVersionIds", {})
    for channel in CHANNELS:
        add(findings, f"M0A12.ANCHOR.VERSION:{channel}", versions.get(channel) != channel_docs.get(channel, {}).get("objectVersionId"))
    schedule = anchor.get("schedule", {})
    add(findings, "M0A12.ANCHOR.SCHEDULE", schedule != {"cadenceSeconds":86400,"graceSeconds":21600,"lapseAfterSeconds":172800,"clock":"utc-rfc3339"})
    try:
        activated_at = parse_time(anchor.get("activatedAt"))
    except Exception:
        activated_at = datetime.max.replace(tzinfo=timezone.utc)
        findings.append("M0A12.ANCHOR.TIME")
    verify_digest(findings, "M0A12.ANCHOR", anchor, "payloadDigest")

    observation = load_required(evidence_root, "observations/000001.json", findings)
    add(findings, "M0A12.OBS.STANDARD", observation.get("standard") != "EIGIIB-M0-A12-OBSERVATION-1.0")
    add(findings, "M0A12.OBS.SEQUENCE", observation.get("sequence") != 1 or observation.get("previousObservationDigest") is not None)
    add(findings, "M0A12.OBS.OBSERVER", observation.get("observerDomainId") != "independent-observer-primary")
    observed_channels = observation.get("channels", [])
    add(findings, "M0A12.OBS.CHANNEL_SET", {c.get("channelId") for c in observed_channels if isinstance(c, dict)} != set(CHANNELS) or len(observed_channels) != 2)
    for item in observed_channels:
        channel = item.get("channelId")
        source = channel_docs.get(channel, {})
        if (
            item.get("providerResourceId") != source.get("providerResourceId")
            or item.get("objectVersionId") != source.get("objectVersionId")
            or item.get("readbackBytes") != BUNDLE_BYTES
            or item.get("readbackSha256") != BUNDLE_SHA256
            or item.get("retentionState") != "applied-and-readback-verified"
            or item.get("result") != "exact-and-retained"
            or not item.get("evidenceRefs")
        ):
            findings.append(f"M0A12.OBS.CHANNEL_DETAIL:{channel}")
    try:
        observed_at = parse_time(observation.get("observedAt"))
        if observed_at < activated_at:
            findings.append("M0A12.OBS.BEFORE_ACTIVATION")
    except Exception:
        findings.append("M0A12.OBS.TIME")
    verify_digest(findings, "M0A12.OBS", observation, "observationDigest")
    verify_signature_for(evidence_root, "observations/000001.json", "independent-observer-primary", findings, "M0A12.OBS")

    evidence_findings = [f for f in findings if f.startswith("M0A12.") and not f.startswith("M0A12.FREEZE")]
    return {
        "present": True,
        "complete": not evidence_findings,
        "observationCount": 1 if not evidence_findings else 0,
        "observationDigest": observation.get("observationDigest"),
    }


def evaluate(root: Path) -> dict[str, Any]:
    findings: list[str] = []
    evaluate_baseline(root, findings)
    authority_count = verify_freeze(root, findings)
    evidence = evaluate_evidence(root, findings)

    if findings:
        structural_result = "nonconformant"
        activation_result = "invalid-or-conflicting-evidence" if evidence.get("present") else "baseline-invalid"
        label = "NT" if evidence.get("present") else "F"
    elif evidence.get("complete"):
        structural_result = "conformant"
        activation_result = "point-in-time-external-activation-and-first-signed-observation-verified"
        label = "T"
    else:
        structural_result = "conformant-preactivation"
        activation_result = "external-evidence-pending"
        label = "NF"

    return {
        "standard": REPORT_STANDARD,
        "structural_result": structural_result,
        "activation_result": activation_result,
        "htntLabel": label,
        "findings": sorted(set(findings)),
        "summary": {
            "m0A11Head": M0_A11_HEAD,
            "stableBundleSha256": BUNDLE_SHA256,
            "providerProfiles": 3,
            "plannedImmutableChannels": 2,
            "requiredExternalDomains": 3,
            "authorityCount": authority_count,
            "evidencePresent": evidence.get("present", False),
            "observationCount": evidence.get("observationCount", 0),
            "e17Decision": "not-ready-for-adoption",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--output")
    parser.add_argument("--require-activated", action="store_true")
    args = parser.parse_args()
    report = evaluate(Path(args.root))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")
    if report["structural_result"] not in {"conformant","conformant-preactivation"}:
        return 1
    if args.require_activated and report["activation_result"] != "point-in-time-external-activation-and-first-signed-observation-verified":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
