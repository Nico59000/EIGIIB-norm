#!/usr/bin/env python3
"""Fail-closed verifier and closure-certificate generator for M0-A12-F1."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from eigiib_m0_a12_f1_canonical import (
    canonical_bytes,
    digest_document,
    inventory_digest,
    sha256_file,
)

STANDARD = "EIGIIB-M0-A12-F1-1.0"
REPORT_STANDARD = "EIGIIB-M0-A12-F1-REPORT-1.0"
CERTIFICATE_STANDARD = "EIGIIB-M0-A12-F1-CLOSURE-CERTIFICATE-1.0"
M0_A12_HEAD = "e6661993924aed4d0185df48cf0b8587b2e0abf3"
M0_A11_HEAD = "148e3e9d06ce791b90e2816d77f5045ebeac0793"
AUTHORITY_PATH = "conformance/m0-a12-f1-bound-ingress.json"
PROTOCOL_PATH = "conformance/m0-a12-f1-htnt-decision-protocol.json"
LEDGER_PATH = "conformance/m0-a12-f1-closure-ledger.json"
FREEZE_PATH = "conformance/m0-a12-f1-authority-freeze.json"
M0_A12_AUTHORITY_PATH = "conformance/m0-a12-external-activation.json"
M0_ROOT = "evidence/m0-a12"
F1_ROOT = "evidence/m0-a12-f1"
MANIFEST = f"{F1_ROOT}/package-manifest.json"
MANIFEST_SIGNATURE = MANIFEST + ".sig"
RECEIPT = f"{F1_ROOT}/ingress-receipt.json"
APPROVAL = f"{F1_ROOT}/operator-approval.json"
APPROVAL_SIGNATURES = {
    "external-preservation-primary": APPROVAL + ".primary.sig",
    "external-preservation-secondary": APPROVAL + ".secondary.sig",
    "independent-observer-primary": APPROVAL + ".observer.sig",
}
CERTIFICATE = f"{F1_ROOT}/closure-certificate.json"
ALLOWED_SIGNERS = f"{M0_ROOT}/keys/allowed_signers.json"
INGRESS_NAMESPACE = "eigiib-m0-a12-f1-ingress@eigiib.example"
APPROVAL_NAMESPACE = "eigiib-m0-a12-f1-approval@eigiib.example"


class ClosureError(RuntimeError):
    pass


def load_object(path: Path, findings: list[str], code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON root is not an object")
        return value
    except Exception as exc:
        findings.append(f"{code}.JSON:{type(exc).__name__}")
        return {}


def add(findings: list[str], code: str, condition: bool) -> None:
    if condition:
        findings.append(code)


def verify_digest(findings: list[str], code: str, value: dict[str, Any], field: str) -> None:
    try:
        expected = digest_document(value, field)
    except Exception:
        findings.append(code + ".CANONICALIZATION")
        return
    if value.get(field) != expected:
        findings.append(code + ".DIGEST")


def verify_freeze(root: Path, findings: list[str]) -> int:
    freeze = load_object(root / FREEZE_PATH, findings, "M0A12F1.FREEZE")
    add(findings, "M0A12F1.FREEZE.STANDARD", freeze.get("standard") != "EIGIIB-M0-A12-F1-AUTHORITY-FREEZE-1.0")
    add(findings, "M0A12F1.FREEZE.SOURCE", freeze.get("sourceHead") != M0_A12_HEAD)
    add(findings, "M0A12F1.FREEZE.EXCLUSION", freeze.get("excludedPath") != FREEZE_PATH)
    authorities = freeze.get("authorities", [])
    add(findings, "M0A12F1.FREEZE.COUNT", freeze.get("authorityCount") != len(authorities))
    seen: set[str] = set()
    for item in authorities if isinstance(authorities, list) else []:
        rel = item.get("path") if isinstance(item, dict) else None
        if not rel or rel == FREEZE_PATH or rel in seen:
            findings.append("M0A12F1.FREEZE.PATH_SET")
            continue
        seen.add(rel)
        path = root / rel
        if not path.is_file():
            findings.append(f"M0A12F1.FREEZE.MISSING:{rel}")
            continue
        if path.stat().st_size != item.get("bytes"):
            findings.append(f"M0A12F1.FREEZE.BYTES:{rel}")
        if sha256_file(path) != item.get("sha256"):
            findings.append(f"M0A12F1.FREEZE.SHA256:{rel}")
    return len(authorities) if isinstance(authorities, list) else 0


def evaluate_baseline(root: Path, findings: list[str]) -> int:
    authority = load_object(root / AUTHORITY_PATH, findings, "M0A12F1.AUTHORITY")
    protocol = load_object(root / PROTOCOL_PATH, findings, "M0A12F1.PROTOCOL")
    ledger = load_object(root / LEDGER_PATH, findings, "M0A12F1.LEDGER")
    m0a12 = load_object(root / M0_A12_AUTHORITY_PATH, findings, "M0A12F1.SOURCE")

    add(findings, "M0A12F1.AUTHORITY.STANDARD", authority.get("standard") != STANDARD)
    add(findings, "M0A12F1.AUTHORITY.STATUS", authority.get("status") != "bound-ingress-gate-established-external-evidence-pack-absent")
    source = authority.get("source", {})
    add(findings, "M0A12F1.SOURCE.M0A12", source.get("m0A12Head") != M0_A12_HEAD)
    add(findings, "M0A12F1.SOURCE.M0A11", source.get("m0A11Head") != M0_A11_HEAD)
    add(findings, "M0A12F1.SOURCE.STANDARD", m0a12.get("standard") != "EIGIIB-M0-A12-1.0")
    successor = m0a12.get("naturalSuccessor", {})
    add(findings, "M0A12F1.SOURCE.SUCCESSOR", successor.get("id") != "M0-A12-F1")

    typed = authority.get("typedDecisionProtocol", {})
    add(findings, "M0A12F1.HTNT.CURRENT", typed.get("currentLabel") != "NF" or typed.get("currentCoordinates") != [1, 0])
    add(findings, "M0A12F1.HTNT.CLOSURE", typed.get("closureLabel") != "T")
    add(findings, "M0A12F1.HTNT.PROMOTION", typed.get("offDiagonalPromotion") != "forbidden")
    package = authority.get("packageContract", {})
    add(findings, "M0A12F1.PACKAGE.ROOT", package.get("packageRoot") != "m0-a12-f1-package")
    add(findings, "M0A12F1.PACKAGE.INVENTORY", package.get("inventoryPolicy") != "closed-exact-no-unlisted-members")
    add(findings, "M0A12F1.PACKAGE.SIGNER", package.get("manifestSigner") != "independent-observer-primary")
    binding = authority.get("bindingProtocol", {})
    add(findings, "M0A12F1.BINDING.CONFIRMATION", binding.get("exactConfirmation") != "BIND-M0-A12-F1-EXTERNAL-EVIDENCE")
    add(findings, "M0A12F1.BINDING.OVERWRITE", binding.get("overwritePolicy") != "deny")
    closure = authority.get("closureProtocol", {})
    add(findings, "M0A12F1.CLOSURE.M0A12", closure.get("requiredM0A12ActivationResult") != "point-in-time-external-activation-and-first-signed-observation-verified")
    add(findings, "M0A12F1.CLOSURE.E17", closure.get("e17Decision") != "not-ready-for-adoption")

    add(findings, "M0A12F1.PROTOCOL.STANDARD", protocol.get("standard") != "EIGIIB-M0-A12-F1-HTNT-DECISION-PROTOCOL-1.0")
    add(findings, "M0A12F1.PROTOCOL.CONTEXT", protocol.get("fixedContext") is not True)
    labels = protocol.get("carrier", {}).get("labels")
    add(findings, "M0A12F1.PROTOCOL.LABELS", labels != {"F": [0, 0], "NF": [1, 0], "NT": [0, 1], "T": [1, 1]})
    obligations = protocol.get("transitionMeasure", {}).get("obligations", [])
    add(findings, "M0A12F1.PROTOCOL.MEASURE", len(obligations) != 5 or len(set(obligations)) != 5)

    add(findings, "M0A12F1.LEDGER.STANDARD", ledger.get("standard") != "EIGIIB-M0-A12-F1-CLOSURE-LEDGER-1.0")
    add(findings, "M0A12F1.LEDGER.STATUS", ledger.get("status") != "external-evidence-pack-absent")
    add(findings, "M0A12F1.LEDGER.SOURCE", ledger.get("sourceHead") != M0_A12_HEAD)
    add(findings, "M0A12F1.LEDGER.PREMATURE", ledger.get("entries") != [] or ledger.get("closureDecision") != "not-closed")
    return verify_freeze(root, findings)


def _verify_signature(
    root: Path,
    payload_rel: str,
    signature_rel: str,
    identity: str,
    namespace: str,
    expected_signed_path: str,
    findings: list[str],
    code: str,
) -> None:
    try:
        from eigiib_m0_a12_signature import SignatureError, verify_file
    except Exception as exc:
        findings.append(f"{code}.CRYPTO:{type(exc).__name__}")
        return
    payload = root / payload_rel
    signature = root / signature_rel
    envelope = load_object(signature, findings, code + ".ENVELOPE")
    add(findings, code + ".PATH", envelope.get("signedPayloadPath") != expected_signed_path)
    try:
        verify_file(payload, signature, root / ALLOWED_SIGNERS, identity, namespace)
    except (OSError, SignatureError) as exc:
        findings.append(f"{code}.SIGNATURE:{type(exc).__name__}")


def _manifest_entries_for_bound_tree(root: Path, manifest: dict[str, Any], findings: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        findings.append("M0A12F1.MANIFEST.ENTRIES")
        return [], []
    projected: list[dict[str, Any]] = []
    paths: list[str] = []
    for item in entries:
        if not isinstance(item, dict):
            findings.append("M0A12F1.MANIFEST.ENTRY_TYPE")
            continue
        projection = {
            "path": item.get("path"),
            "bytes": item.get("bytes"),
            "sha256": item.get("sha256"),
            "role": item.get("role"),
            "mediaType": item.get("mediaType"),
        }
        path = projection["path"]
        if not isinstance(path, str) or not path.startswith("payload/evidence/"):
            findings.append("M0A12F1.MANIFEST.PATH")
            continue
        paths.append(path)
        target = root / path.removeprefix("payload/")
        if not target.is_file():
            findings.append(f"M0A12F1.MANIFEST.MISSING:{path}")
        else:
            if target.stat().st_size != projection["bytes"]:
                findings.append(f"M0A12F1.MANIFEST.BYTES:{path}")
            if sha256_file(target) != projection["sha256"]:
                findings.append(f"M0A12F1.MANIFEST.SHA256:{path}")
        projected.append(projection)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        findings.append("M0A12F1.MANIFEST.ORDER_OR_DUPLICATE")

    declared_m0 = {
        item["path"].removeprefix("payload/")
        for item in projected
        if isinstance(item.get("path"), str) and item["path"].startswith("payload/evidence/m0-a12/")
    }
    actual_m0 = {
        path.relative_to(root).as_posix()
        for path in (root / M0_ROOT).rglob("*")
        if path.is_file()
    } if (root / M0_ROOT).is_dir() else set()
    if declared_m0 != actual_m0:
        findings.append("M0A12F1.MANIFEST.M0A12_CLOSED_SET")

    expected_f1_payload = {
        APPROVAL,
        *APPROVAL_SIGNATURES.values(),
    }
    declared_f1 = {
        item["path"].removeprefix("payload/")
        for item in projected
        if isinstance(item.get("path"), str) and item["path"].startswith("payload/evidence/m0-a12-f1/")
    }
    if declared_f1 != expected_f1_payload:
        findings.append("M0A12F1.MANIFEST.F1_PAYLOAD_SET")
    evidence_entries = [item for item in projected if item["path"].startswith("payload/evidence/m0-a12/")]
    return projected, evidence_entries


def evaluate_bound(
    root: Path,
    findings: list[str],
    m0a12_evaluator: Callable[[Path], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    m0_exists = (root / M0_ROOT).exists()
    f1_exists = (root / F1_ROOT).exists()
    if not m0_exists and not f1_exists:
        return {"present": False, "readyForCertificate": False, "certificatePresent": False}
    if not m0_exists or not f1_exists:
        findings.append("M0A12F1.EVIDENCE.PARTIAL_ROOT")
        return {"present": True, "readyForCertificate": False, "certificatePresent": (root / CERTIFICATE).is_file()}

    required = [MANIFEST, MANIFEST_SIGNATURE, RECEIPT, APPROVAL, ALLOWED_SIGNERS, *APPROVAL_SIGNATURES.values()]
    for rel in required:
        if not (root / rel).is_file():
            findings.append(f"M0A12F1.EVIDENCE.MISSING:{rel}")
    if any(code.startswith("M0A12F1.EVIDENCE.MISSING") for code in findings):
        return {"present": True, "readyForCertificate": False, "certificatePresent": (root / CERTIFICATE).is_file()}

    manifest = load_object(root / MANIFEST, findings, "M0A12F1.MANIFEST")
    add(findings, "M0A12F1.MANIFEST.STANDARD", manifest.get("standard") != "EIGIIB-M0-A12-F1-EVIDENCE-PACK-MANIFEST-1.0")
    add(findings, "M0A12F1.MANIFEST.SOURCE", manifest.get("sourceAuthorityHead") != M0_A12_HEAD)
    verify_digest(findings, "M0A12F1.MANIFEST", manifest, "manifestDigest")
    projected, evidence_entries = _manifest_entries_for_bound_tree(root, manifest, findings)
    add(findings, "M0A12F1.MANIFEST.PAYLOAD_SET", manifest.get("payloadSetDigest") != inventory_digest(projected) if projected else True)
    add(findings, "M0A12F1.MANIFEST.EVIDENCE_SET", manifest.get("evidenceSetDigest") != inventory_digest(evidence_entries) if evidence_entries else True)
    _verify_signature(
        root,
        MANIFEST,
        MANIFEST_SIGNATURE,
        "independent-observer-primary",
        INGRESS_NAMESPACE,
        "manifest.json",
        findings,
        "M0A12F1.MANIFEST",
    )

    receipt = load_object(root / RECEIPT, findings, "M0A12F1.RECEIPT")
    add(findings, "M0A12F1.RECEIPT.STANDARD", receipt.get("standard") != "EIGIIB-M0-A12-F1-INGRESS-RECEIPT-1.0")
    add(findings, "M0A12F1.RECEIPT.SOURCE", receipt.get("sourceAuthorityHead") != M0_A12_HEAD)
    add(findings, "M0A12F1.RECEIPT.RESULT", receipt.get("result") != "verified-and-bound")
    add(findings, "M0A12F1.RECEIPT.MANIFEST", receipt.get("manifestDigest") != manifest.get("manifestDigest"))
    add(findings, "M0A12F1.RECEIPT.PAYLOAD", receipt.get("payloadSetDigest") != manifest.get("payloadSetDigest"))
    add(findings, "M0A12F1.RECEIPT.EVIDENCE", receipt.get("evidenceSetDigest") != manifest.get("evidenceSetDigest"))
    add(findings, "M0A12F1.RECEIPT.ENTRY_COUNT", receipt.get("entryCount") != len(projected))
    verify_digest(findings, "M0A12F1.RECEIPT", receipt, "receiptDigest")

    approval = load_object(root / APPROVAL, findings, "M0A12F1.APPROVAL")
    add(findings, "M0A12F1.APPROVAL.STANDARD", approval.get("standard") != "EIGIIB-M0-A12-F1-OPERATOR-APPROVAL-1.0")
    add(findings, "M0A12F1.APPROVAL.SOURCE", approval.get("sourceAuthorityHead") != M0_A12_HEAD)
    add(findings, "M0A12F1.APPROVAL.EVIDENCE", approval.get("evidenceSetDigest") != manifest.get("evidenceSetDigest"))
    add(findings, "M0A12F1.APPROVAL.DECISION", approval.get("decision") != "approve-exact-binding-and-point-in-time-closure-attempt")
    add(findings, "M0A12F1.APPROVAL.IRREVERSIBLE", approval.get("irreversibleProviderActionsAcknowledged") is not True)
    verify_digest(findings, "M0A12F1.APPROVAL", approval, "approvalDigest")
    for identity, rel in APPROVAL_SIGNATURES.items():
        _verify_signature(
            root,
            APPROVAL,
            rel,
            identity,
            APPROVAL_NAMESPACE,
            "operator-approval.json",
            findings,
            f"M0A12F1.APPROVAL:{identity}",
        )

    if m0a12_evaluator is None:
        try:
            from eigiib_m0_a12_check import evaluate as m0a12_evaluator
        except Exception as exc:
            findings.append(f"M0A12F1.M0A12.IMPORT:{type(exc).__name__}")
            m0a12_report = {}
        else:
            m0a12_report = m0a12_evaluator(root)
    else:
        m0a12_report = m0a12_evaluator(root)
    add(findings, "M0A12F1.M0A12.RESULT", m0a12_report.get("activation_result") != "point-in-time-external-activation-and-first-signed-observation-verified")
    add(findings, "M0A12F1.M0A12.HTNT", m0a12_report.get("htntLabel") != "T")
    add(findings, "M0A12F1.M0A12.FINDINGS", m0a12_report.get("findings") != [])
    report_digest = sha256_file_bytes(canonical_bytes(m0a12_report))

    pre_certificate_findings = list(findings)
    ready = not pre_certificate_findings
    certificate_present = (root / CERTIFICATE).is_file()
    if certificate_present:
        certificate = load_object(root / CERTIFICATE, findings, "M0A12F1.CERTIFICATE")
        add(findings, "M0A12F1.CERTIFICATE.STANDARD", certificate.get("standard") != CERTIFICATE_STANDARD)
        add(findings, "M0A12F1.CERTIFICATE.SOURCE", certificate.get("sourceAuthorityHead") != M0_A12_HEAD)
        add(findings, "M0A12F1.CERTIFICATE.RECEIPT", certificate.get("ingressReceiptDigest") != receipt.get("receiptDigest"))
        add(findings, "M0A12F1.CERTIFICATE.MANIFEST", certificate.get("manifestDigest") != manifest.get("manifestDigest"))
        add(findings, "M0A12F1.CERTIFICATE.EVIDENCE", certificate.get("evidenceSetDigest") != manifest.get("evidenceSetDigest"))
        add(findings, "M0A12F1.CERTIFICATE.REPORT", certificate.get("m0A12ReportDigest") != report_digest)
        add(findings, "M0A12F1.CERTIFICATE.DECISION", certificate.get("closureDecision") != "point-in-time-m0-a12-activation-closed")
        add(findings, "M0A12F1.CERTIFICATE.HTNT", certificate.get("htntTransition") != ["NF", "T"])
        add(findings, "M0A12F1.CERTIFICATE.E17", certificate.get("e17Decision") != "not-ready-for-adoption")
        verify_digest(findings, "M0A12F1.CERTIFICATE", certificate, "certificateDigest")

    return {
        "present": True,
        "readyForCertificate": ready,
        "certificatePresent": certificate_present,
        "manifestDigest": manifest.get("manifestDigest"),
        "evidenceSetDigest": manifest.get("evidenceSetDigest"),
        "receiptDigest": receipt.get("receiptDigest"),
        "m0A12Report": m0a12_report,
        "m0A12ReportDigest": report_digest,
    }


def sha256_file_bytes(value: bytes) -> str:
    import hashlib
    return hashlib.sha256(value).hexdigest()


def evaluate(
    root: Path,
    m0a12_evaluator: Callable[[Path], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    findings: list[str] = []
    authority_count = evaluate_baseline(root, findings)
    baseline_findings = list(findings)
    bound = evaluate_bound(root, findings, m0a12_evaluator)

    if findings:
        structural_result = "nonconformant"
        closure_result = "invalid-or-conflicting-bound-evidence" if bound.get("present") else "baseline-invalid"
        label = "NT" if bound.get("present") else "F"
    elif not bound.get("present"):
        structural_result = "conformant-ingress-gate"
        closure_result = "external-evidence-pack-absent"
        label = "NF"
    elif bound.get("readyForCertificate") and not bound.get("certificatePresent"):
        structural_result = "conformant-preclosure"
        closure_result = "external-evidence-bound-closure-certificate-pending"
        label = "NT"
    else:
        structural_result = "conformant"
        closure_result = "point-in-time-m0-a12-activation-closed"
        label = "T"

    return {
        "standard": REPORT_STANDARD,
        "structural_result": structural_result,
        "closure_result": closure_result,
        "htntLabel": label,
        "findings": sorted(set(findings)),
        "summary": {
            "m0A12Head": M0_A12_HEAD,
            "m0A11Head": M0_A11_HEAD,
            "authorityCount": authority_count,
            "externalEvidencePresent": bool(bound.get("present")),
            "readyForClosureCertificate": bool(bound.get("readyForCertificate")),
            "closureCertificatePresent": bool(bound.get("certificatePresent")),
            "e17Decision": "not-ready-for-adoption",
        },
    }


def write_certificate(
    root: Path,
    closed_at: str,
    m0a12_evaluator: Callable[[Path], dict[str, Any]] | None = None,
) -> Path:
    findings: list[str] = []
    evaluate_baseline(root, findings)
    bound = evaluate_bound(root, findings, m0a12_evaluator)
    if findings:
        raise ClosureError("cannot finalize nonconformant bound evidence: " + ", ".join(sorted(set(findings))))
    if not bound.get("present") or not bound.get("readyForCertificate"):
        raise ClosureError("bound evidence is not ready for closure certification")
    path = root / CERTIFICATE
    if path.exists():
        raise ClosureError("closure certificate already exists")
    certificate = {
        "standard": CERTIFICATE_STANDARD,
        "sourceAuthorityHead": M0_A12_HEAD,
        "ingressReceiptDigest": bound["receiptDigest"],
        "manifestDigest": bound["manifestDigest"],
        "evidenceSetDigest": bound["evidenceSetDigest"],
        "m0A12ReportDigest": bound["m0A12ReportDigest"],
        "closureDecision": "point-in-time-m0-a12-activation-closed",
        "htntTransition": ["NF", "T"],
        "closedAt": closed_at,
        "e17Decision": "not-ready-for-adoption",
        "claimBoundary": "point-in-time-only-not-long-horizon-preservation",
        "certificateDigest": "",
    }
    certificate["certificateDigest"] = digest_document(certificate, "certificateDigest")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(certificate, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--output")
    parser.add_argument("--require-closed", action="store_true")
    parser.add_argument("--write-closure-certificate", action="store_true")
    parser.add_argument("--closed-at")
    args = parser.parse_args()
    root = Path(args.root)
    try:
        if args.write_closure_certificate:
            if not args.closed_at:
                raise ClosureError("--closed-at is required when writing a closure certificate")
            write_certificate(root, args.closed_at)
        report = evaluate(root)
    except ClosureError as exc:
        print(json.dumps({"standard": "EIGIIB-M0-A12-F1-CLOSURE-ERROR-1.0", "result": "rejected", "error": str(exc)}, indent=2))
        return 1
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")
    if report["structural_result"] not in {"conformant-ingress-gate", "conformant-preclosure", "conformant"}:
        return 1
    if args.require_closed and report["closure_result"] != "point-in-time-m0-a12-activation-closed":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
