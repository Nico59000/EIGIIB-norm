#!/usr/bin/env python3
"""Bind the exact P1-A5 verifier implementation and CI closure."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A5-hardening-0.2"
PROFILE = "p1-a5-independent-source-closure-v1"
TOOL_VERSION = "0.2.0"
BASELINE_CHAIN_IDENTITY = {
    "algorithm": "sha256",
    "digest": "8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d",
    "bytes": 2182,
}
IMPLEMENTATIONS = [
    ("go-module", "independent/go.mod"),
    ("go-cli", "independent/cmd/eigiib-p1-independent/main.go"),
    ("go-cbor", "independent/p1verify/cbor.go"),
    ("go-core", "independent/p1verify/core.go"),
    ("go-json-manifest", "independent/p1verify/json_manifest.go"),
    ("go-p1a1-p1a2", "independent/p1verify/p1a1_a2.go"),
    ("go-p1a3", "independent/p1verify/p1a3.go"),
    ("python-differential-checker", "tools/eigiib_verifier_matrix.py"),
    ("matrix-manifest", "tests/fixtures/p1-a5/matrix.json"),
    ("canonical-independent-result", "tests/fixtures/p1-a5/expected-independent-result.json"),
    ("structural-state", "conformance/p1-a5-verifier-matrix.json"),
    ("line-ending-policy", ".gitattributes"),
    ("cross-platform-workflow", ".github/workflows/p1-a5-matrix.yml"),
    ("hardening-checker", "tools/eigiib_verifier_matrix_hardening_check.py"),
]
ACTION_PINS = [
    {"name": "actions/checkout", "sha": "d23441a48e516b6c34aea4fa41551a30e30af803"},
    {"name": "actions/setup-python", "sha": "ece7cb06caefa5fff74198d8649806c4678c61a1"},
    {"name": "actions/setup-go", "sha": "924ae3a1cded613372ab5595356fb5720e22ba16"},
]
RUNNERS = ["ubuntu-24.04", "macos-15", "windows-2025"]
BOUNDARIES = [
    "exact-source-closure-does-not-imply-trusted-go-toolchain-binaries",
    "exact-workflow-bytes-do-not-imply-trusted-github-runner-image",
    "pinned-action-commit-does-not-imply-action-or-platform-source-authenticity",
    "source-identity-does-not-imply-independent-trust-roots",
    "cross-platform-agreement-does-not-imply-production-equivalence",
    "p1-a5-h0.2-does-not-replace-upstream-p1-or-e-authorities",
]


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def strict_json_loads(raw: bytes, label: str) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=hook,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except Exception as exc:
        raise ValueError(f"{label}: {exc}") from exc


def identity(raw: bytes) -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "digest": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def confined_regular_file(root: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute():
        raise ValueError("path must be repository-relative")
    normalized = Path(os.path.normpath(relative))
    if normalized == Path("..") or (normalized.parts and normalized.parts[0] == ".."):
        raise ValueError("implementation path escapes repository root")
    candidate = root / normalized
    current = root
    for part in normalized.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("implementation path contains a symlink")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("implementation path escapes repository root") from exc
    if not resolved.is_file():
        raise ValueError("implementation path is not a regular file")
    return resolved


def validate_manifest(root: Path, manifest: Any) -> list[dict[str, Any]]:
    if not isinstance(manifest, dict):
        raise ValueError("hardening manifest root must be object")
    expected_fields = {
        "standard",
        "profile",
        "baselineChainIdentity",
        "toolchainDeclaration",
        "implementations",
        "claimBoundary",
    }
    if set(manifest) != expected_fields:
        raise ValueError("hardening manifest fields differ from contract")
    if manifest.get("standard") != STANDARD or manifest.get("profile") != PROFILE:
        raise ValueError("hardening manifest constants differ from contract")
    if manifest.get("baselineChainIdentity") != BASELINE_CHAIN_IDENTITY:
        raise ValueError("baseline chain identity differs from P1-A4")
    toolchain = manifest.get("toolchainDeclaration")
    expected_toolchain = {
        "goVersion": "1.26.5",
        "pythonVersion": "3.13",
        "opensslMode": "system-provider-reference-route-only",
        "actions": ACTION_PINS,
        "runners": RUNNERS,
    }
    if toolchain != expected_toolchain:
        raise ValueError("toolchain declaration differs from closed P1-A5 profile")
    boundary = manifest.get("claimBoundary")
    if boundary != {
        "authority": "p1_verifier_matrix_contract",
        "doesNotImply": BOUNDARIES,
    }:
        raise ValueError("hardening claim boundary differs from contract")
    rows = manifest.get("implementations")
    if not isinstance(rows, list) or len(rows) != len(IMPLEMENTATIONS):
        raise ValueError("implementation closure cardinality differs from contract")
    expected_pairs = list(IMPLEMENTATIONS)
    observed_pairs: list[tuple[str, str]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"role", "path", "identity"}:
            raise ValueError("implementation entry fields differ from contract")
        observed_pairs.append((row.get("role"), row.get("path")))
        path = confined_regular_file(root, row.get("path"))
        if row.get("identity") != identity(path.read_bytes()):
            raise ValueError(f"implementation identity mismatch: {row.get('path')}")
    if observed_pairs != expected_pairs:
        raise ValueError("implementation roles or order differ from contract")
    return rows


def run_baseline(root: Path, go: str, openssl: str) -> tuple[bool, str]:
    command = [
        sys.executable,
        "tools/eigiib_verifier_matrix.py",
        "check",
        ".",
        "--go",
        go,
        "--openssl",
        openssl,
        "--json",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return False, str(exc)
    if completed.returncode != 0:
        return False, completed.stderr.decode(errors="replace").strip() or "P1-A5 baseline failed"
    try:
        result = strict_json_loads(completed.stdout, "P1A5H.BASELINE")
    except ValueError as exc:
        return False, str(exc)
    expected = {
        "structural_result": "conformant",
        "matrix_contract_result": "conformant",
        "reference_route_result": "conformant",
        "reference_closure_result": "conformant",
        "independent_route_result": "conformant",
        "differential_result": "equivalent",
        "expected_projection_result": "conformant",
    }
    if not isinstance(result, dict) or any(result.get(k) != v for k, v in expected.items()):
        return False, "P1-A5 baseline result carriers are not all positive"
    return True, ""


def check_repository(root: Path, go: str = "go", openssl: str = "openssl") -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []
    binding_result = "not-evaluated"
    baseline_result = "not-evaluated"
    manifest_path = root / "tests/fixtures/p1-a5/implementation-set.json"
    try:
        manifest = strict_json_loads(manifest_path.read_bytes(), "P1A5H.MANIFEST")
        validate_manifest(root, manifest)
        binding_result = "valid"
    except (OSError, ValueError) as exc:
        findings.append(
            Finding("error", "P1A5H.IMPLEMENTATION.CLOSURE", str(manifest_path), str(exc))
        )
    if not findings:
        valid, message = run_baseline(root, go, openssl)
        if valid:
            baseline_result = "conformant"
        else:
            baseline_result = "invalid"
            findings.append(
                Finding("error", "P1A5H.BASELINE.REPLAY", "tools/eigiib_verifier_matrix.py", message)
            )
    return {
        "tool": "eigiib-verifier-matrix-hardening",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if findings else "conformant",
        "implementation_binding_result": binding_result,
        "baseline_matrix_result": baseline_result,
        "hardening_result": "non-conformant" if findings else "conformant",
        "trust_result": "not-evaluated-by-p1-a5-h0.2",
        "toolchain_binary_identity_result": "not-provided-by-p1-a5-h0.2",
        "runner_image_identity_result": "not-provided-by-p1-a5-h0.2",
        "findings": [asdict(item) for item in sorted(findings)],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--go", default="go")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    output = check_repository(args.root, args.go, args.openssl)
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(output["hardening_result"])
        for finding in output["findings"]:
            print(f"{finding['severity']}: {finding['code']}: {finding['path']}: {finding['message']}")
    return 0 if output["hardening_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
