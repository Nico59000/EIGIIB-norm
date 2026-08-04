#!/usr/bin/env python3
"""Structural conformance checker for M0-A11 preparatory authority."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from eigiib_m0_a11_observe import evaluate, parse_time

STANDARD = "EIGIIB-M0-A11-1.0"
REPORT_STANDARD = "EIGIIB-M0-A11-REPORT-1.0"
M0_A10_HEAD = "2891265f04a5d9a4d69c134fa48881b0ed93fe13"
BUNDLE_SHA256 = "96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
AUTHORITY_PATH = "conformance/m0-a11-external-evidence-preparation.json"
REGISTRY_PATH = "conformance/m0-a11-control-domain-registry.json"
CHANNEL_PATH = "conformance/m0-a11-immutable-channel-bootstrap.json"
CAMPAIGN_PATH = "conformance/m0-a11-observation-campaign.json"
LEDGER_PATH = "conformance/m0-a11-observation-ledger.json"
FREEZE_PATH = "conformance/m0-a11-authority-freeze.json"
M0A10_PATH = "conformance/m0-a10-dual-channel-publication.json"
REQUIRED_DIMS = [
    "provider-operator", "tenant-account", "identity-root", "privileged-administrator",
    "billing-authority", "credential-store", "execution-plane", "region-or-failure-domain",
    "audit-log-custody",
]
REQUIRED_NONCLAIMS = {
    "external-provider-selected", "external-account-created", "external-authority-attested",
    "immutable-channel-provisioned", "retention-lock-enforced", "legal-hold-enforced",
    "administrative-deletion-prevented", "independent-observer-bound",
    "signed-observation-captured", "long-horizon-preservation-observed",
    "correlated-failure-resistance-established", "provider-independence-established", "e17-adoption",
}


def load(root: Path, rel: str) -> dict[str, Any]:
    return json.loads((root / rel).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate_authority(root: Path) -> dict[str, Any]:
    findings: list[str] = []
    try:
        authority = load(root, AUTHORITY_PATH)
        registry = load(root, REGISTRY_PATH)
        channels = load(root, CHANNEL_PATH)
        campaign = load(root, CAMPAIGN_PATH)
        ledger = load(root, LEDGER_PATH)
        m0a10 = load(root, M0A10_PATH)
    except Exception as exc:
        return {"standard": REPORT_STANDARD, "structural_result": "nonconformant", "findings": [f"M0A11.JSON:{type(exc).__name__}"], "summary": {}}

    if authority.get("standard") != STANDARD:
        findings.append("M0A11.AUTHORITY.STANDARD")
    if authority.get("status") != "external-evidence-acquisition-prepared-not-activated":
        findings.append("M0A11.AUTHORITY.STATUS")
    source = authority.get("source", {})
    if source.get("m0A10Head") != M0_A10_HEAD:
        findings.append("M0A11.SOURCE.M0A10_HEAD")
    if source.get("m0A10AuthorityPath") != M0A10_PATH:
        findings.append("M0A11.SOURCE.M0A10_PATH")
    if source.get("stableBundle", {}).get("sha256") != BUNDLE_SHA256:
        findings.append("M0A11.SOURCE.BUNDLE")
    if m0a10.get("standard") != "EIGIIB-M0-A10-1.0" or m0a10.get("status") != "bounded-external-publication-and-readback-verified":
        findings.append("M0A11.SOURCE.M0A10_AUTHORITY")
    if m0a10.get("naturalSuccessor", {}).get("decision") != "not-ready-for-adoption":
        findings.append("M0A11.SOURCE.E17_BOUNDARY")

    boundary = authority.get("claimBoundary", {})
    for key in ["preparatoryOnly", "declaredConfigurationIsNotObservedEvidence", "providerLabelIsNotControlIndependence", "retentionIntentIsNotImmutability", "scheduledObservationIsNotCompletedObservation"]:
        if boundary.get(key) is not True:
            findings.append(f"M0A11.BOUNDARY:{key}")
    if boundary.get("unknownExternalFacts") != "deny":
        findings.append("M0A11.BOUNDARY.UNKNOWN")
    if set(authority.get("nonclaims", [])) != REQUIRED_NONCLAIMS:
        findings.append("M0A11.NONCLAIMS")
    if authority.get("entryGates", {}).get("e17", {}).get("decision") != "not-ready-for-adoption":
        findings.append("M0A11.E17.PREMATURE_ADOPTION")
    if authority.get("entryGates", {}).get("m0A12", {}).get("decision") != "ready-for-external-activation-only":
        findings.append("M0A11.SUCCESSOR.DECISION")

    if registry.get("standard") != "EIGIIB-M0-A11-CONTROL-DOMAIN-REGISTRY-1.0":
        findings.append("M0A11.REGISTRY.STANDARD")
    if registry.get("requiredControlDimensions") != REQUIRED_DIMS:
        findings.append("M0A11.REGISTRY.DIMENSIONS")
    domains = {d.get("id"): d for d in registry.get("domains", []) if isinstance(d, dict)}
    expected = {"github-existing-publication-domain", "external-preservation-primary", "external-preservation-secondary", "independent-observer-primary"}
    if set(domains) != expected:
        findings.append("M0A11.REGISTRY.DOMAIN_SET")
    for domain_id in ["external-preservation-primary", "external-preservation-secondary", "independent-observer-primary"]:
        domain = domains.get(domain_id, {})
        if domain.get("bindingState") != "unbound" or domain.get("providerBinding") != "unbound" or domain.get("attestationPath") is not None:
            findings.append(f"M0A11.REGISTRY.PREMATURE_BINDING:{domain_id}")
        dims = domain.get("controlDimensions", {})
        if set(dims) != set(REQUIRED_DIMS) or any(value != "unbound" for value in dims.values()):
            findings.append(f"M0A11.REGISTRY.CONTROL_DIMENSIONS:{domain_id}")
    observer = domains.get("independent-observer-primary", {})
    if "preservation-custodian" not in observer.get("prohibitedRoles", []) or "publication-authority" not in observer.get("prohibitedRoles", []):
        findings.append("M0A11.REGISTRY.OBSERVER_ROLE_SEPARATION")
    rules = registry.get("independenceRules", {})
    for key in ["unknownDimension", "sameProviderOperator", "sameTenantAccount", "sameIdentityRoot", "samePrivilegedAdministrator", "sameBillingAuthority", "sameCredentialStore", "sameExecutionPlane"]:
        if not str(rules.get(key, "")).startswith("not-independent"):
            findings.append(f"M0A11.REGISTRY.RULE:{key}")

    if channels.get("activationState") != "not-activated" or channels.get("status") != "bootstrap-contracts-prepared-no-channel-provisioned":
        findings.append("M0A11.CHANNELS.ACTIVATION")
    channel_docs = channels.get("channels", [])
    if len(channel_docs) != 2:
        findings.append("M0A11.CHANNELS.COUNT")
    domain_refs: list[str] = []
    for channel in channel_docs:
        cid = channel.get("id", "unknown")
        domain_refs.append(channel.get("controlDomainId"))
        if channel.get("lifecycleState") != "planned-not-provisioned":
            findings.append(f"M0A11.CHANNEL.PREMATURE_STATE:{cid}")
        if channel.get("endpoint") != "unbound" or channel.get("providerResourceId") != "unbound" or channel.get("objectVersionId") != "unbound":
            findings.append(f"M0A11.CHANNEL.PREMATURE_RESOURCE:{cid}")
        if channel.get("artifact", {}).get("sha256") != BUNDLE_SHA256:
            findings.append(f"M0A11.CHANNEL.ARTIFACT:{cid}")
        retention = channel.get("retention", {})
        if retention.get("policyState") != "not-applied" or retention.get("minimumWindowSeconds") != "unbound":
            findings.append(f"M0A11.CHANNEL.PREMATURE_RETENTION:{cid}")
        if retention.get("modeRequirement") != "compliance-lock-or-equivalent-non-bypassable-retention":
            findings.append(f"M0A11.CHANNEL.LOCK_REQUIREMENT:{cid}")
        if channel.get("deploymentEvidence") != []:
            findings.append(f"M0A11.CHANNEL.PREMATURE_EVIDENCE:{cid}")
    if domain_refs != ["external-preservation-primary", "external-preservation-secondary"]:
        findings.append("M0A11.CHANNELS.DOMAIN_BINDING")

    if campaign.get("activationState") != "not-activated" or campaign.get("activatedAt") is not None:
        findings.append("M0A11.CAMPAIGN.PREMATURE_ACTIVATION")
    if campaign.get("observerDomainId") != "independent-observer-primary":
        findings.append("M0A11.CAMPAIGN.OBSERVER")
    schedule = campaign.get("schedule", {})
    if schedule.get("cadenceSeconds") != 86400 or schedule.get("graceSeconds") != 21600 or schedule.get("lapseAfterSeconds") != 172800:
        findings.append("M0A11.CAMPAIGN.SCHEDULE")
    if schedule.get("lapseAfterSeconds", 0) <= schedule.get("graceSeconds", 0):
        findings.append("M0A11.CAMPAIGN.LAPSE_THRESHOLDS")
    if ledger.get("campaignState") != "not-activated" or ledger.get("observations") != []:
        findings.append("M0A11.LEDGER.PREMATURE_EVIDENCE")
    lapse = evaluate(campaign, ledger, parse_time("2026-08-04T00:00:00Z"))
    if lapse.get("state") != "not-activated" or lapse.get("findings"):
        findings.append("M0A11.HARNESS.PREPARATORY_STATE")

    try:
        freeze = load(root, FREEZE_PATH)
        if freeze.get("standard") != "EIGIIB-M0-A11-AUTHORITY-FREEZE-1.0" or freeze.get("source_head") != M0_A10_HEAD:
            findings.append("M0A11.FREEZE.HEADER")
        authorities = freeze.get("authorities", [])
        if freeze.get("authority_count") != len(authorities) or freeze.get("excluded_path") != FREEZE_PATH:
            findings.append("M0A11.FREEZE.COUNT")
        seen: set[str] = set()
        for item in authorities:
            rel = item.get("path")
            if not rel or rel in seen or rel == FREEZE_PATH:
                findings.append("M0A11.FREEZE.PATH_SET")
                continue
            seen.add(rel)
            path = root / rel
            if not path.is_file():
                findings.append(f"M0A11.FREEZE.MISSING:{rel}")
                continue
            if path.stat().st_size != item.get("bytes"):
                findings.append(f"M0A11.FREEZE.BYTES:{rel}")
            if sha256(path) != item.get("sha256"):
                findings.append(f"M0A11.FREEZE.SHA256:{rel}")
    except Exception as exc:
        findings.append(f"M0A11.FREEZE.JSON:{type(exc).__name__}")

    result = "conformant" if not findings else "nonconformant"
    return {
        "standard": REPORT_STANDARD,
        "structural_result": result,
        "findings": sorted(set(findings)),
        "summary": {
            "m0A10Head": M0_A10_HEAD,
            "preparatoryStatus": authority.get("status"),
            "registeredDomains": len(domains),
            "plannedImmutableChannels": len(channel_docs),
            "campaignActivationState": campaign.get("activationState"),
            "observationCount": len(ledger.get("observations", [])),
            "e17Decision": authority.get("entryGates", {}).get("e17", {}).get("decision"),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--output")
    args = parser.parse_args()
    report = evaluate_authority(Path(args.root))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
