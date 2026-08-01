#!/usr/bin/env python3
"""Bind the exact executable closure consumed by EIGIIB P1-A4."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

import eigiib_interop_chain as baseline
from eigiib_interop_chain_contract import identity, strict_json_loads

TOOL_VERSION = "0.2.0"
STANDARD = "EIGIIB-P1-A4-hardening-0.2"
PROFILE = "p1-a4-executable-closure-v1"
BASELINE_CHAIN_IDENTITY = {
    "algorithm": "sha256",
    "digest": "8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d",
    "bytes": 2182,
}
IMPLEMENTATION_CONTRACT = [
    ("p1-a1-checker", "tools/eigiib_in_toto_capsule.py"),
    ("p1-a2-checker", "tools/eigiib_sigstore_bundle.py"),
    ("p1-a3-baseline-checker", "tools/eigiib_scitt_receipt.py"),
    ("p1-a3-hardening-checker", "tools/eigiib_scitt_receipt_hardening_check.py"),
    ("p1-a4-orchestrator", "tools/eigiib_interop_chain.py"),
    ("p1-a4-contract", "tools/eigiib_interop_chain_contract.py"),
    ("p1-a4-validation", "tools/eigiib_interop_chain_validation.py"),
    ("p1-a4-hardening-checker", "tools/eigiib_interop_chain_hardening_check.py"),
]
BOUNDARIES = [
    "byte-exact-replay-closure-does-not-imply-trusted-python-interpreter",
    "byte-exact-replay-closure-does-not-imply-trusted-openssl-provider",
    "implementation-identity-does-not-imply-source-authenticity",
    "exact-checker-bytes-do-not-imply-production-environment-equivalence",
    "p1-a4-h0.2-does-not-replace-upstream-authorities",
]
TOP_FIELDS = {"standard", "profile", "baselineChainIdentity", "implementations", "claimBoundary"}
IMPL_FIELDS = {"role", "path", "identity"}
BOUNDARY_FIELDS = {"authority", "doesNotImply"}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def valid_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"algorithm", "digest", "bytes"}
        and value.get("algorithm") == "sha256"
        and isinstance(value.get("digest"), str)
        and len(value["digest"]) == 64
        and all(ch in "0123456789abcdef" for ch in value["digest"])
        and isinstance(value.get("bytes"), int)
        and not isinstance(value.get("bytes"), bool)
        and value["bytes"] > 0
    )


def confined(root: Path, rel: str) -> Path:
    if not isinstance(rel, str) or not rel or Path(rel).is_absolute():
        raise ValueError("path must be a non-empty repository-relative string")
    path = (root / rel).resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes repository root") from exc
    return path


def result(findings: list[Finding], implementation_result: str, baseline_result: str) -> dict[str, Any]:
    failed = bool(findings)
    return {
        "tool": "eigiib-interop-chain-hardening",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if failed else "conformant",
        "implementation_binding_result": implementation_result,
        "baseline_replay_result": baseline_result,
        "hardening_result": "non-conformant" if failed else "conformant",
        "findings": [asdict(item) for item in sorted(findings)],
    }


def validate_hardening(root: Path, manifest: Any, baseline_runner: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []

    def add(code: str, path: str, message: str) -> None:
        findings.append(Finding("error", code, path, message))

    if not isinstance(manifest, dict):
        return result([Finding("error", "P1A4H.MANIFEST.TYPE", "", "manifest root must be an object")], "not-evaluated", "not-evaluated")
    if set(manifest) != TOP_FIELDS:
        add("P1A4H.MANIFEST.FIELD", "", "hardening manifest fields do not match P1-A4-H0.2")
    if manifest.get("standard") != STANDARD or manifest.get("profile") != PROFILE:
        add("P1A4H.MANIFEST.CONST", "", "standard or profile mismatch")
    if manifest.get("baselineChainIdentity") != BASELINE_CHAIN_IDENTITY:
        add("P1A4H.BASELINE.CHAIN_IDENTITY", "baselineChainIdentity", "baseline chain identity mismatch")

    boundary = manifest.get("claimBoundary")
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_FIELDS:
        add("P1A4H.BOUNDARY.FIELD", "claimBoundary", "claim boundary fields do not match P1-A4-H0.2")
    elif boundary.get("authority") != "p1_chain_contract" or boundary.get("doesNotImply") != BOUNDARIES:
        add("P1A4H.BOUNDARY.WEAKENED", "claimBoundary", "negative implication boundary must match P1-A4-H0.2 exactly")

    implementations = manifest.get("implementations")
    expected_roles = [role for role, _ in IMPLEMENTATION_CONTRACT]
    observed_roles = [item.get("role") if isinstance(item, dict) else None for item in implementations] if isinstance(implementations, list) else []
    if observed_roles != expected_roles:
        add("P1A4H.IMPLEMENTATION.ORDER", "implementations", "implementation closure must appear once in fixed order")
    else:
        for index, (item, (role, expected_path)) in enumerate(zip(implementations, IMPLEMENTATION_CONTRACT)):
            loc = f"implementations[{index}]"
            if set(item) != IMPL_FIELDS:
                add("P1A4H.IMPLEMENTATION.FIELD", loc, "implementation fields do not match P1-A4-H0.2")
                continue
            if item.get("path") != expected_path:
                add("P1A4H.IMPLEMENTATION.PATH", f"{loc}.path", "implementation path differs from fixed closure")
                continue
            if not valid_identity(item.get("identity")):
                add("P1A4H.IMPLEMENTATION.IDENTITY", f"{loc}.identity", "invalid implementation identity")
                continue
            try:
                path = confined(root, expected_path)
                if not path.is_file():
                    raise ValueError("implementation file is missing")
                observed = identity(path.read_bytes())
                if observed != item["identity"]:
                    add("P1A4H.IMPLEMENTATION.IDENTITY_MISMATCH", expected_path, "implementation identity differs from exact file bytes")
            except (OSError, ValueError) as exc:
                add("P1A4H.IMPLEMENTATION.FILE", expected_path, str(exc))

    if findings:
        return result(findings, "invalid", "not-evaluated")

    implementation_result = "valid"
    try:
        upstream = baseline_runner()
    except Exception as exc:
        add("P1A4H.BASELINE.ERROR", "p1-a4", str(exc))
        return result(findings, implementation_result, "invalid")
    required = {
        "tool": "eigiib-interop-chain",
        "tool_version": "0.1.0",
        "standard": "EIGIIB-P1-A4-1.0",
        "structural_result": "conformant",
        "manifest_binding_result": "conformant",
        "p1a1_replay_result": "conformant",
        "p1a2_replay_result": "conformant",
        "p1a3_replay_result": "conformant",
        "cross_capsule_binding_result": "conformant",
        "end_to_end_result": "conformant",
        "chain_identity": BASELINE_CHAIN_IDENTITY,
    }
    if not isinstance(upstream, dict) or any(upstream.get(key) != value for key, value in required.items()):
        add("P1A4H.BASELINE.RESULT", "p1-a4", "baseline P1-A4 output does not match the hardened result contract")
        return result(findings, implementation_result, "invalid")
    return result([], implementation_result, "valid")


def check_repository(root: Path, openssl: str = "openssl") -> dict[str, Any]:
    root = root.resolve()
    manifest_path = root / "tests/fixtures/p1-a4/implementation-set.json"
    if not manifest_path.is_file():
        return result([Finding("error", "P1A4H.REPO.MISSING", str(manifest_path), "implementation-set manifest is missing")], "not-evaluated", "not-evaluated")
    try:
        manifest = strict_json_loads(manifest_path.read_bytes(), "P1A4H.REPO.MANIFEST")
    except ValueError as exc:
        return result([Finding("error", "P1A4H.REPO.PARSE", str(manifest_path), str(exc))], "not-evaluated", "not-evaluated")
    return validate_hardening(root, manifest, lambda: baseline.check_repository(root, openssl))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = check_repository(args.root, args.openssl)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(out["hardening_result"])
        for item in out["findings"]:
            print(f"{item['severity']}: {item['code']}: {item['path']}: {item['message']}")
    return 0 if out["hardening_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
