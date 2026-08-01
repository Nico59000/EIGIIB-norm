#!/usr/bin/env python3
"""Validate the additive P1-A6 external native verifier bridge."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A6-1.0"
PROFILE = "external-native-verifier-bridge-v1"
TOOL_VERSION = "0.1.0"
CHAIN_IDENTITY = {
    "algorithm": "sha256",
    "digest": "8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d",
    "bytes": 2182,
}
A5_EXPECTED_IDENTITY = {
    "algorithm": "sha256",
    "digest": "97d4860f26ace2b259119d3fd293fa5a0156573d946ebd0ebc1878f5f4f083d9",
    "bytes": 715,
}
A6_EXPECTED_IDENTITY = {
    "algorithm": "sha256",
    "digest": "9d1c0e22aec9b4259194d53ea5c154d884ba3f49c3e4482e5b89e575f1702682",
    "bytes": 896,
}
RUNNERS = ["ubuntu-24.04", "macos-15", "windows-2025"]
BOUNDARIES = [
    "external-library-acceptance-does-not-imply-eigiib-claim-truth",
    "external-cose-verification-does-not-imply-trusted-issuer-or-transparency-service",
    "partial-external-observation-does-not-imply-third-complete-independent-implementation",
    "dependency-version-does-not-imply-byte-exact-toolchain-identity",
    "fixture-observation-does-not-imply-production-interoperability",
    "p1-a6-does-not-replace-p1-a1-through-p1-a5-or-e-authorities",
]
PROJECTION_FIELDS = [
    "manifest_binding_result",
    "p1a1_replay_result",
    "p1a2_replay_result",
    "p1a3_replay_result",
    "cross_capsule_binding_result",
    "end_to_end_result",
    "chain_identity",
]


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def strict_json_loads(raw: bytes, label: str) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError(f"duplicate JSON member: {key}")
            output[key] = value
        return output

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


def confined(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("path must be a non-empty repository-relative string")
    candidate = (root / relative).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes repository root") from exc
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("path contains a symlink")
    if not candidate.is_file():
        raise ValueError("path is not a regular file")
    return candidate


def validate_manifest(root: Path, manifest: Any) -> tuple[Path, dict[str, Any], Path]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "standard",
        "profile",
        "status",
        "baseline",
        "externalObservation",
        "expectedResult",
        "requiredRunners",
        "claimBoundary",
    }:
        raise ValueError("bridge manifest fields differ from P1-A6 contract")
    if (
        manifest.get("standard") != STANDARD
        or manifest.get("profile") != PROFILE
        or manifest.get("status") != "fixture-observation"
    ):
        raise ValueError("bridge manifest constants differ from P1-A6 contract")
    baseline = manifest.get("baseline")
    if baseline != {
        "standard": "EIGIIB-P1-A5-1.0",
        "hardeningChecker": "tools/eigiib_verifier_matrix_hardening_check.py",
        "expectedProjection": {
            "path": "tests/fixtures/p1-a5/expected-independent-result.json",
            "identity": A5_EXPECTED_IDENTITY,
        },
        "chainIdentity": CHAIN_IDENTITY,
    }:
        raise ValueError("P1-A5 baseline binding differs from P1-A6 contract")
    observation = manifest.get("externalObservation")
    if observation != {
        "id": "veraison-go-cose-p1-a3",
        "module": "github.com/veraison/go-cose",
        "version": "v1.3.0",
        "entrypoint": "external/cmd/eigiib-p1-external",
        "scope": "p1-a3-cose-sign1-and-receipt",
        "networkMode": "dependency-download-only",
        "runtimeNetworkOperations": False,
    }:
        raise ValueError("external observation declaration differs from P1-A6 contract")
    if manifest.get("requiredRunners") != RUNNERS:
        raise ValueError("required runner matrix differs from P1-A6 contract")
    if manifest.get("claimBoundary") != {
        "authority": "p1_external_bridge_contract",
        "doesNotImply": BOUNDARIES,
    }:
        raise ValueError("claim boundary differs from P1-A6 contract")

    projection_row = baseline["expectedProjection"]
    projection_path = confined(root, projection_row["path"])
    if identity(projection_path.read_bytes()) != projection_row["identity"]:
        raise ValueError("P1-A5 expected projection identity differs from exact bytes")
    expected_projection = strict_json_loads(
        projection_path.read_bytes(), "P1A6.BASELINE.EXPECTED"
    )
    if not isinstance(expected_projection, dict):
        raise ValueError("P1-A5 expected projection must be an object")

    expected_row = manifest.get("expectedResult")
    if expected_row != {
        "path": "tests/fixtures/p1-a6/expected-external-result.json",
        "identity": A6_EXPECTED_IDENTITY,
    }:
        raise ValueError("P1-A6 expected result binding differs from contract")
    expected_path = confined(root, expected_row["path"])
    if identity(expected_path.read_bytes()) != expected_row["identity"]:
        raise ValueError("P1-A6 expected result identity differs from exact bytes")
    return projection_path, expected_projection, expected_path


def projection(value: dict[str, Any]) -> dict[str, Any]:
    return {field: value.get(field) for field in PROJECTION_FIELDS}


def run_json(command: list[str], cwd: Path) -> tuple[int, dict[str, Any] | None, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return 127, None, str(exc)
    stderr = completed.stderr.decode(errors="replace").strip()
    try:
        output = strict_json_loads(completed.stdout, "P1A6.SUBPROCESS")
    except ValueError:
        output = None
    return completed.returncode, output if isinstance(output, dict) else None, stderr


def result(findings: list[Finding], states: dict[str, str]) -> dict[str, Any]:
    return {
        "tool": "eigiib-external-verifier-bridge",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if findings else "conformant",
        "bridge_contract_result": states.get("contract", "not-evaluated"),
        "p1_a5_hardening_result": states.get("baseline", "not-evaluated"),
        "external_observation_result": states.get("external", "not-evaluated"),
        "external_library_result": states.get("library", "not-evaluated"),
        "projection_equivalence_result": states.get("projection", "not-evaluated"),
        "cross_platform_matrix_result": "required-by-p1-a6-ci",
        "trust_result": "not-evaluated-by-p1-a6",
        "production_interoperability_result": "not-evaluated-by-p1-a6",
        "findings": [asdict(item) for item in sorted(findings)],
    }


def check_repository(
    root: Path, go: str = "go", openssl: str = "openssl"
) -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []
    states: dict[str, str] = {}
    manifest_path = root / "tests/fixtures/p1-a6/bridge.json"
    state_path = root / "conformance/p1-a6-external-native.json"
    try:
        manifest = strict_json_loads(manifest_path.read_bytes(), "P1A6.MANIFEST")
        _, expected_projection, expected_path = validate_manifest(root, manifest)
        states["contract"] = "conformant"
    except (OSError, ValueError) as exc:
        findings.append(Finding("error", "P1A6.MANIFEST.INVALID", str(manifest_path), str(exc)))
        return result(findings, states)

    expected_state = {
        "standard": STANDARD,
        "status": "structural-only",
        "profile": PROFILE,
        "bridge_manifest": "tests/fixtures/p1-a6/bridge.json",
        "baseline": "P1-A5-H0.2",
        "external_library": "github.com/veraison/go-cose@v1.3.0",
        "observation_scope": "p1-a3-cose-sign1-and-receipt",
        "required_runners": RUNNERS,
        "runtime_network_operations": [],
        "production_replays": [],
    }
    try:
        observed_state = strict_json_loads(state_path.read_bytes(), "P1A6.STATE")
        if observed_state != expected_state:
            raise ValueError("structural state differs from P1-A6 contract")
    except (OSError, ValueError) as exc:
        findings.append(Finding("error", "P1A6.STATE.INVALID", str(state_path), str(exc)))

    returncode, hardened, stderr = run_json(
        [
            sys.executable,
            "tools/eigiib_verifier_matrix_hardening_check.py",
            ".",
            "--go",
            go,
            "--openssl",
            openssl,
            "--json",
        ],
        root,
    )
    if (
        returncode != 0
        or not hardened
        or hardened.get("hardening_result") != "conformant"
        or hardened.get("implementation_binding_result") != "valid"
        or hardened.get("baseline_matrix_result") != "conformant"
    ):
        states["baseline"] = "invalid"
        findings.append(
            Finding(
                "error",
                "P1A6.BASELINE.HARDENING",
                "tools/eigiib_verifier_matrix_hardening_check.py",
                stderr or "P1-A5-H0.2 baseline failed",
            )
        )
    else:
        states["baseline"] = "conformant"

    returncode, external, stderr = run_json(
        [
            go,
            "run",
            "./cmd/eigiib-p1-external",
            "-root",
            "..",
            "-expected",
            "../tests/fixtures/p1-a6/expected-external-result.json",
        ],
        root / "external",
    )
    if (
        returncode != 0
        or not external
        or external.get("structural_result") != "conformant"
        or external.get("external_observation_result") != "conformant"
        or external.get("external_library_result") != "valid"
        or external.get("end_to_end_result") != "conformant"
    ):
        states["external"] = "invalid"
        states["library"] = "invalid"
        findings.append(
            Finding(
                "error",
                "P1A6.EXTERNAL.ROUTE",
                "external/cmd/eigiib-p1-external",
                stderr or "external native observation failed",
            )
        )
    else:
        states["external"] = "conformant"
        states["library"] = "valid"

    if external is not None:
        if projection(external) != projection(expected_projection):
            states["projection"] = "divergent"
            findings.append(
                Finding(
                    "error",
                    "P1A6.PROJECTION.DIVERGENCE",
                    str(expected_path),
                    "external native result differs from the closed P1-A5 projection",
                )
            )
        else:
            states["projection"] = "equivalent"
    return result(findings, states)


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
        print(output["structural_result"])
        for finding in output["findings"]:
            print(
                f"{finding['severity']}: {finding['code']}: "
                f"{finding['path']}: {finding['message']}"
            )
    return 0 if output["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
