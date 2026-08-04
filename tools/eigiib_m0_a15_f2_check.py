#!/usr/bin/env python3
"""Repository, ingress and point-in-time T-closure gate for M0-A15-F2."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from eigiib_m0_a15_f1_canonical import bytes_digest, load_json, safe_repo_path
from eigiib_m0_a15_f2_replay import F1_HEAD, F1_TREE, verify_activation_package

FREEZE_PATH = "conformance/m0-a15-f2-authority-freeze.json"
DEFAULT_PACKAGE_PATH = "evidence/m0-a15-f2/activation-package.json"
REQUIRED = (
    "conformance/m0-a15-f2-authority.json",
    "conformance/m0-a15-f2-policy.json",
    "conformance/m0-a15-f2-ledger.json",
    "conformance/m0-a15-f2-htnt-decision-protocol.json",
)
EXPECTED_AUTHORITIES = tuple(sorted((
    ".github/workflows/m0-a15-f2-external-history-activation.yml",
    "conformance/M0-A15-F2-MANUAL-REVIEW.md",
    "conformance/m0-a15-f2-authority.json",
    "conformance/m0-a15-f2-htnt-decision-protocol.json",
    "conformance/m0-a15-f2-ledger.json",
    "conformance/m0-a15-f2-policy.json",
    "docs/M0-A15-F2-EXTERNAL-AUTHENTICATED-HISTORY-INGRESS-EXACT-A14-REPLAY-POINT-IN-TIME-ACTIVATION-AND-T-CLOSURE.md",
    "docs/M0-A15-F2-OPERATOR-RUNBOOK.md",
    "schemas/eigiib-m0-a15-f2-activation-package.schema.json",
    "schemas/eigiib-m0-a15-f2-principal-profile.schema.json",
    "schemas/eigiib-m0-a15-f2-signed-envelope.schema.json",
    "tests/fixtures/m0-a15-f2/expected-baseline-report.json",
    "tests/m0_a15_f2_cases.py",
    "tests/test_eigiib_m0_a15_f2.py",
    "tools/eigiib_m0_a15_f2_check.py",
    "tools/eigiib_m0_a15_f2_replay.py",
)))
SCHEMA_PATHS = tuple(path for path in EXPECTED_AUTHORITIES if path.startswith("schemas/"))
F1_FREEZE_PATH = "conformance/m0-a15-f1-authority-freeze.json"


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


def verify_parent_f1(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        tree = _git(root, "rev-parse", f"{F1_HEAD}^{{tree}}")
        if tree != F1_TREE:
            errors.append("source-f1-tree-mismatch")
        current = _git(root, "rev-parse", "HEAD")
        seen: set[str] = set()
        while current != F1_HEAD:
            if current in seen:
                raise RuntimeError("first-parent-cycle")
            seen.add(current)
            line = _git(root, "rev-list", "--parents", "-n", "1", current)
            parts = line.split()
            if len(parts) < 2:
                raise RuntimeError("source-f1-not-on-first-parent-lineage")
            current = parts[1]
        freeze_raw = _git_file(root, F1_HEAD, F1_FREEZE_PATH)
        freeze = json.loads(freeze_raw.decode("utf-8"))
    except Exception:
        return ["source-f1-materialization-failed"]
    entries = freeze.get("authorities", []) if isinstance(freeze, dict) else []
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if freeze.get("authorityCount") != len(entries):
        errors.append("source-f1-freeze-count-mismatch")
    if len(paths) != len(entries) or len(paths) != len(set(paths)):
        errors.append("source-f1-freeze-path-inventory-invalid")
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not safe_repo_path(path):
            errors.append("source-f1-freeze-path-invalid")
            continue
        try:
            raw = _git_file(root, F1_HEAD, path)
        except Exception:
            errors.append("source-f1-authority-missing")
            continue
        if len(raw) != entry.get("bytes") or bytes_digest(raw) != entry.get("sha256"):
            errors.append("source-f1-authority-digest-mismatch")
    return sorted(set(errors))


def verify_f2_freeze(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        freeze = load_json(root / FREEZE_PATH)
    except Exception:
        return ["f2-authority-freeze-invalid"]
    entries = freeze.get("authorities", []) if isinstance(freeze, dict) else []
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if freeze.get("sourceHead") != F1_HEAD or freeze.get("sourceTree") != F1_TREE:
        errors.append("f2-authority-freeze-source-mismatch")
    if freeze.get("excludedPath") != FREEZE_PATH:
        errors.append("f2-authority-freeze-self-exclusion-invalid")
    if freeze.get("authorityCount") != len(entries):
        errors.append("f2-authority-freeze-count-mismatch")
    if tuple(paths) != EXPECTED_AUTHORITIES:
        errors.append("f2-authority-freeze-inventory-mismatch")
    if len(paths) != len(set(paths)) or any(not safe_repo_path(path) for path in paths):
        errors.append("f2-authority-freeze-path-invalid")
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not safe_repo_path(path):
            continue
        file_path = root / path
        if not file_path.is_file():
            errors.append("f2-authority-freeze-path-missing")
            continue
        raw = file_path.read_bytes()
        if len(raw) != entry.get("bytes") or bytes_digest(raw) != entry.get("sha256"):
            errors.append("f2-authority-freeze-digest-mismatch")
    return sorted(set(errors))


def validate_package_schema(root: Path, package: Any) -> list[str]:
    try:
        schemas = [load_json(root / path) for path in SCHEMA_PATHS]
        resources = [(schema["$id"], Resource.from_contents(schema)) for schema in schemas]
        registry = Registry().with_resources(resources)
        package_schema = next(
            schema for schema in schemas
            if schema.get("$id", "").endswith("eigiib-m0-a15-f2-activation-package.schema.json")
        )
        validator = Draft202012Validator(
            package_schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
        return sorted(
            f"schema:{'/'.join(str(part) for part in error.absolute_path) or '$'}:{error.validator}"
            for error in validator.iter_errors(package)
        )
    except Exception as exc:
        return [f"schema-validator-failed:{type(exc).__name__}"]


def evaluate(
    root: Path | str = ".",
    package_path: Path | str | None = None,
    evaluation_at: str | None = None,
) -> dict[str, Any]:
    root = Path(root)
    findings: list[str] = []
    documents: dict[str, Any] = {}
    try:
        documents = {path: load_json(root / path) for path in REQUIRED}
    except Exception as exc:
        findings.append(f"f2-authority-load-failed:{type(exc).__name__}")

    findings.extend(verify_parent_f1(root))
    findings.extend(verify_f2_freeze(root))
    if documents:
        authority = documents[REQUIRED[0]]
        policy = documents[REQUIRED[1]]
        ledger = documents[REQUIRED[2]]
        protocol = documents[REQUIRED[3]]
        if authority.get("source", {}).get("m0A15F1Head") != F1_HEAD or authority.get("source", {}).get("m0A15F1Tree") != F1_TREE:
            findings.append("f2-authority-source-mismatch")
        if policy.get("activationDecision") != "exact-f1-t-then-point-in-time-signed-closure" or policy.get("hostClockReads") != "forbidden":
            findings.append("f2-policy-invalid")
        if ledger.get("sourceHead") != F1_HEAD or ledger.get("entries") != [] or ledger.get("activationCount") != 0:
            findings.append("f2-baseline-ledger-not-empty")
        if protocol.get("current", {}).get("label") != "NF":
            findings.append("f2-protocol-baseline-invalid")

    package_file = Path(package_path) if package_path is not None else root / DEFAULT_PACKAGE_PATH
    if package_path is not None and not package_file.is_absolute():
        package_file = root / package_file

    replay: dict[str, Any] | None = None
    if package_file.exists():
        try:
            package = load_json(package_file)
            schema_errors = validate_package_schema(root, package)
            if schema_errors:
                replay = {"verified": False, "errors": schema_errors, "summary": {}}
            else:
                replay = verify_activation_package(package, root, evaluation_at)
        except Exception as exc:
            replay = {
                "verified": False,
                "errors": [f"activation-package-evaluation-failed:{type(exc).__name__}"],
                "summary": {},
            }

    if findings:
        label = "F"
        decision = "invalid"
        report_findings = sorted(set(findings))
    elif replay is None:
        label = "NF"
        decision = "external-authenticated-activation-not-observed"
        report_findings = []
    elif replay.get("verified"):
        label = "T"
        decision = "external-authenticated-history-exact-a14-replay-and-point-in-time-activation-verified"
        report_findings = []
    else:
        label = "NT"
        decision = "external-activation-incomplete-or-invalid"
        report_findings = list(replay.get("errors", []))

    summary = replay.get("summary", {}) if replay else {}
    return {
        "standard": "EIGIIB-M0-A15-F2-REPORT-1.0",
        "htntLabel": label,
        "decision": decision,
        "findings": report_findings,
        "summary": {
            "sourceF1": "verified" if not findings else "invalid",
            "exactA14Replay": "verified" if label == "T" else "not-observed" if replay is None else "not-verified",
            "ingressAuthentication": "verified" if label == "T" else "not-observed" if replay is None else "not-verified",
            "independentIngressReadback": "verified" if label == "T" else "not-observed" if replay is None else "not-verified",
            "pointInTimeActivation": "verified" if label == "T" else "not-observed" if replay is None else "not-verified",
            "activationWitnessQuorum": "verified" if label == "T" else "not-observed" if replay is None else "not-verified",
            "activationReadback": "verified" if label == "T" else "not-observed" if replay is None else "not-verified",
            "historyDigest": summary.get("historyDigest"),
            "f1ReportDigest": summary.get("f1ReportDigest"),
            "activationDigest": summary.get("activationDigest"),
            "activatedAt": summary.get("activatedAt"),
            "validUntil": summary.get("validUntil"),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--package")
    parser.add_argument("--at")
    parser.add_argument("--output")
    parser.add_argument("--require-t", action="store_true")
    args = parser.parse_args()
    report = evaluate(args.root, args.package, args.at)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if not args.require_t or report["htntLabel"] == "T" else 2


if __name__ == "__main__":
    raise SystemExit(main())
