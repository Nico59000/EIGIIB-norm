#!/usr/bin/env python3
"""Repository and evidence gate for M0-A15-F1."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from eigiib_m0_a15_f1_canonical import bytes_digest, load_json, safe_repo_path
from eigiib_m0_a15_f1_replay import A15_HEAD, A15_TREE, verify_case

FREEZE_PATH = "conformance/m0-a15-f1-authority-freeze.json"
DEFAULT_EVIDENCE_PATH = "evidence/m0-a15-f1/authenticated-history.json"
REQUIRED = (
    "conformance/m0-a15-f1-authority.json",
    "conformance/m0-a15-f1-policy.json",
    "conformance/m0-a15-f1-ledger.json",
    "conformance/m0-a15-f1-htnt-decision-protocol.json",
)
EXPECTED_AUTHORITIES = (
    ".github/workflows/m0-a15-f1-authenticated-evidence-binding.yml",
    "conformance/M0-A15-F1-MANUAL-REVIEW.md",
    "conformance/m0-a15-f1-authority.json",
    "conformance/m0-a15-f1-htnt-decision-protocol.json",
    "conformance/m0-a15-f1-ledger.json",
    "conformance/m0-a15-f1-policy.json",
    "docs/M0-A15-F1-AUTHENTICATED-MULTI-REGISTRY-EVIDENCE-BINDING-DERIVED-SPLIT-BRAIN-PROOF-AND-EXACT-A14-CONTINUITY-REPLAY.md",
    "docs/M0-A15-F1-OPERATOR-RUNBOOK.md",
    "schemas/eigiib-m0-a15-f1-derived-split-brain-proof.schema.json",
    "schemas/eigiib-m0-a15-f1-evidence.schema.json",
    "schemas/eigiib-m0-a15-f1-observer-profile.schema.json",
    "schemas/eigiib-m0-a15-f1-reconciliation-record.schema.json",
    "schemas/eigiib-m0-a15-f1-registry-profile.schema.json",
    "schemas/eigiib-m0-a15-f1-signed-envelope.schema.json",
    "schemas/eigiib-m0-a15-f1-witness-profile.schema.json",
    "tests/fixtures/m0-a15-f1/expected-baseline-report.json",
    "tests/m0_a15_f1_cases.py",
    "tests/test_eigiib_m0_a15_f1.py",
    "tools/eigiib_m0_a15_f1_canonical.py",
    "tools/eigiib_m0_a15_f1_check.py",
    "tools/eigiib_m0_a15_f1_checkpoints.py",
    "tools/eigiib_m0_a15_f1_crypto.py",
    "tools/eigiib_m0_a15_f1_historical_a14.py",
    "tools/eigiib_m0_a15_f1_model.py",
    "tools/eigiib_m0_a15_f1_principals.py",
    "tools/eigiib_m0_a15_f1_replay.py",
)
SCHEMA_PATHS = tuple(path for path in EXPECTED_AUTHORITIES if path.startswith("schemas/"))


def _git(root: Path, *args: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def _git_file(root: Path, commit: str, path: str) -> bytes:
    return _git(root, "show", f"{commit}:{path}", binary=True)  # type: ignore[return-value]


def verify_parent_a15(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        tree = _git(root, "rev-parse", f"{A15_HEAD}^{{tree}}")
        if tree != A15_TREE:
            errors.append("source-a15-tree-mismatch")
        current = _git(root, "rev-parse", "HEAD")
        seen: set[str] = set()
        while current != A15_HEAD:
            if current in seen:
                raise RuntimeError("first-parent-cycle")
            seen.add(current)
            line = _git(root, "rev-list", "--parents", "-n", "1", current)
            parts = line.split()
            if len(parts) < 2:
                raise RuntimeError("source-a15-not-on-first-parent-lineage")
            current = parts[1]
        freeze_raw = _git_file(root, A15_HEAD, "conformance/m0-a15-authority-freeze.json")
        freeze = json.loads(freeze_raw.decode("utf-8"))
    except Exception:
        return ["source-a15-materialization-failed"]
    entries = freeze.get("authorities", []) if isinstance(freeze, dict) else []
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if freeze.get("authorityCount") != len(entries):
        errors.append("source-a15-freeze-count-mismatch")
    if len(paths) != len(entries) or len(paths) != len(set(paths)):
        errors.append("source-a15-freeze-path-inventory-invalid")
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not safe_repo_path(path):
            errors.append("source-a15-freeze-path-invalid")
            continue
        try:
            raw = _git_file(root, A15_HEAD, path)
        except Exception:
            errors.append("source-a15-authority-missing")
            continue
        if len(raw) != entry.get("bytes") or bytes_digest(raw) != entry.get("sha256"):
            errors.append("source-a15-authority-digest-mismatch")
    return sorted(set(errors))


def verify_f1_freeze(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        freeze = load_json(root / FREEZE_PATH)
    except Exception:
        return ["f1-authority-freeze-invalid"]
    entries = freeze.get("authorities", []) if isinstance(freeze, dict) else []
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if freeze.get("sourceHead") != A15_HEAD or freeze.get("sourceTree") != A15_TREE:
        errors.append("f1-authority-freeze-source-mismatch")
    if freeze.get("excludedPath") != FREEZE_PATH:
        errors.append("f1-authority-freeze-self-exclusion-invalid")
    if freeze.get("authorityCount") != len(entries):
        errors.append("f1-authority-freeze-count-mismatch")
    if tuple(paths) != EXPECTED_AUTHORITIES:
        errors.append("f1-authority-freeze-inventory-mismatch")
    if len(paths) != len(set(paths)) or any(not safe_repo_path(path) for path in paths):
        errors.append("f1-authority-freeze-path-invalid")
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not safe_repo_path(path):
            continue
        file_path = root / path
        if not file_path.is_file():
            errors.append("f1-authority-freeze-path-missing")
            continue
        raw = file_path.read_bytes()
        if len(raw) != entry.get("bytes") or bytes_digest(raw) != entry.get("sha256"):
            errors.append("f1-authority-freeze-digest-mismatch")
    return sorted(set(errors))


def validate_evidence_schema(root: Path, evidence: Any) -> list[str]:
    try:
        schemas = [load_json(root / path) for path in SCHEMA_PATHS]
        resources = [(schema["$id"], Resource.from_contents(schema)) for schema in schemas]
        registry = Registry().with_resources(resources)
        evidence_schema = next(
            schema for schema in schemas
            if schema.get("$id", "").endswith("eigiib-m0-a15-f1-evidence.schema.json")
        )
        validator = Draft202012Validator(
            evidence_schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
        return sorted(
            f"schema:{'/'.join(str(part) for part in error.absolute_path) or '$'}:{error.validator}"
            for error in validator.iter_errors(evidence)
        )
    except Exception as exc:
        return [f"schema-validator-failed:{type(exc).__name__}"]


def evaluate(root: Path | str = ".", evidence_path: Path | str | None = None) -> dict[str, Any]:
    root = Path(root)
    findings: list[str] = []
    documents: dict[str, Any] = {}
    try:
        documents = {path: load_json(root / path) for path in REQUIRED}
    except Exception as exc:
        findings.append(f"f1-authority-load-failed:{type(exc).__name__}")

    findings.extend(verify_parent_a15(root))
    findings.extend(verify_f1_freeze(root))
    if documents:
        authority = documents[REQUIRED[0]]
        policy = documents[REQUIRED[1]]
        ledger = documents[REQUIRED[2]]
        protocol = documents[REQUIRED[3]]
        if authority.get("source", {}).get("m0A15Head") != A15_HEAD or authority.get("source", {}).get("m0A15Tree") != A15_TREE:
            findings.append("f1-authority-source-mismatch")
        if policy.get("signatureAlgorithm") != "ed25519" or policy.get("splitBrainDecision") != "derive-from-authenticated-receipts":
            findings.append("f1-policy-invalid")
        if ledger.get("sourceHead") != A15_HEAD or ledger.get("entries") != [] or ledger.get("checkpointCount") != 0:
            findings.append("f1-baseline-ledger-not-empty")
        if protocol.get("current", {}).get("label") != "NF":
            findings.append("f1-protocol-baseline-invalid")

    evidence_file = Path(evidence_path) if evidence_path is not None else root / DEFAULT_EVIDENCE_PATH
    if evidence_path is not None and not evidence_file.is_absolute():
        evidence_file = root / evidence_file

    replay: dict[str, Any] | None = None
    if evidence_file.exists():
        try:
            evidence = load_json(evidence_file)
            schema_errors = validate_evidence_schema(root, evidence)
            if schema_errors:
                replay = {"verified": False, "errors": schema_errors, "summary": {}}
            else:
                replay = verify_case(evidence, root)
        except Exception as exc:
            replay = {"verified": False, "errors": [f"evidence-evaluation-failed:{type(exc).__name__}"], "summary": {}}

    if findings:
        label = "F"
        decision = "invalid"
        report_findings = sorted(set(findings))
    elif replay is None:
        label = "NF"
        decision = "authenticated-evidence-not-observed"
        report_findings = []
    elif replay.get("verified"):
        label = "T"
        decision = "authenticated-evidence-and-derived-reconciliation-verified"
        report_findings = []
    else:
        label = "NT"
        decision = "authenticated-evidence-incomplete-or-invalid"
        report_findings = list(replay.get("errors", []))

    summary = replay.get("summary", {}) if replay else {}
    return {
        "standard": "EIGIIB-M0-A15-F1-REPORT-1.0",
        "htntLabel": label,
        "decision": decision,
        "findings": report_findings,
        "summary": {
            "sourceA15": "verified" if not findings else "invalid",
            "a14Replay": "verified" if label == "T" else "not-observed" if replay is None else "not-verified",
            "checkpointCount": summary.get("checkpointCount", 0),
            "registryReceiptCount": summary.get("registryReceiptCount", 0),
            "splitBrainProofCount": summary.get("splitBrainProofCount", 0),
            "reconciliationRecordCount": summary.get("reconciliationRecordCount", 0),
            "governanceReconciliationCount": summary.get("governanceReconciliationCount", 0),
            "observedSpanSeconds": summary.get("observedSpanSeconds", 0),
            "latestCheckpointDigest": summary.get("latestCheckpointDigest"),
            "longTermCertificateDigest": summary.get("longTermCertificateDigest"),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--evidence")
    parser.add_argument("--output")
    parser.add_argument("--require-verified", action="store_true")
    args = parser.parse_args()
    report = evaluate(args.root, args.evidence)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if not args.require_verified or report["htntLabel"] == "T" else 2


if __name__ == "__main__":
    raise SystemExit(main())
