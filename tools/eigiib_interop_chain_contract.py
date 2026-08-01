"""Shared contract and helpers for EIGIIB P1-A4."""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-P1-A4-1.0"
PROFILE = "p1-end-to-end-cross-capsule-replay-v1"
CHAIN_STATUS = "fixture-replay"
IDENTITY_FIELDS = {"algorithm", "digest", "bytes"}
TOP_FIELDS = {"standard", "profile", "status", "components", "keys", "replay", "claimBoundary"}
COMPONENT_FIELDS = {"id", "path", "standard", "identity"}
KEY_FIELDS = {"id", "path", "role", "spkiIdentity"}
REPLAY_FIELDS = {"order", "subjectName", "checkers", "chainIdentity"}
CHECKER_FIELDS = {"id", "path", "toolVersion"}
BOUNDARY_FIELDS = {"authority", "compositionOnly", "doesNotImply"}
COMPONENT_IDS = ["m0-a2-report", "p1-a1-statement", "p1-a2-bundle", "p1-a3-signed-statement", "p1-a3-receipt"]
COMPONENT_PATHS = {
    "m0-a2-report": "tests/fixtures/p1-a1/aggregate.json",
    "p1-a1-statement": "tests/fixtures/p1-a1/capsule.json",
    "p1-a2-bundle": "tests/fixtures/p1-a2/bundle.json",
    "p1-a3-signed-statement": "tests/fixtures/p1-a3/capsule.json",
    "p1-a3-receipt": "tests/fixtures/p1-a3/capsule.json",
}
COMPONENT_STANDARDS = {
    "m0-a2-report": "EIGIIB-M0-A2-1.0",
    "p1-a1-statement": "EIGIIB-P1-A1-1.0",
    "p1-a2-bundle": "EIGIIB-P1-A2-1.0",
    "p1-a3-signed-statement": "EIGIIB-P1-A3-1.0",
    "p1-a3-receipt": "EIGIIB-P1-A3-1.0",
}
KEY_IDS = ["p1-a2-public-key", "p1-a3-issuer-key", "p1-a3-transparency-service-key"]
KEY_CONTRACT = {
    "p1-a2-public-key": ("tests/fixtures/p1-a2/public-key.pem", "p1-a2-signer"),
    "p1-a3-issuer-key": ("tests/fixtures/p1-a3/issuer-public-key.pem", "scitt-issuer"),
    "p1-a3-transparency-service-key": ("tests/fixtures/p1-a3/ts-public-key.pem", "scitt-transparency-service"),
}
REPLAY_ORDER = ["p1-a1", "p1-a2", "p1-a3-h0.2"]
CHECKER_CONTRACT = {
    "p1-a1": ("tools/eigiib_in_toto_capsule.py", "0.2.0"),
    "p1-a2": ("tools/eigiib_sigstore_bundle.py", "0.1.1"),
    "p1-a3-h0.2": ("tools/eigiib_scitt_receipt_hardening_check.py", "0.2.0"),
}
SUBJECT_NAME = "tests/fixtures/p1-a1/aggregate.json"
BOUNDARIES = [
    "end-to-end-replay-does-not-imply-eigiib-claim-truth",
    "all-capsules-valid-does-not-imply-production-conformance",
    "signature-validity-does-not-imply-trusted-or-authorized-signers",
    "receipt-bound-registration-does-not-imply-global-append-only-consistency",
    "single-chain-replay-does-not-imply-e6-cross-view-convergence",
    "registration-order-does-not-imply-e11-trusted-time",
    "chain-identity-does-not-imply-source-authenticity",
    "fixture-portability-does-not-imply-live-service-interoperability",
    "p1-a4-composition-does-not-replace-p1-a1-p1-a2-p1-a3-authorities",
]


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def strict_json_loads(raw: bytes, code: str) -> Any:
    def hook(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=hook,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"non-finite JSON number: {x}")))
    except Exception as exc:
        raise ValueError(f"{code}: {exc}") from exc


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def identity(raw: bytes) -> dict[str, Any]:
    return {"algorithm": "sha256", "digest": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def valid_identity(obj: Any) -> bool:
    return (isinstance(obj, dict) and set(obj) == IDENTITY_FIELDS and obj.get("algorithm") == "sha256"
            and isinstance(obj.get("digest"), str) and len(obj["digest"]) == 64
            and all(c in "0123456789abcdef" for c in obj["digest"])
            and isinstance(obj.get("bytes"), int) and not isinstance(obj.get("bytes"), bool) and obj["bytes"] > 0)


def confined(root: Path, rel: Any) -> Path:
    if not isinstance(rel, str) or not rel or Path(rel).is_absolute():
        raise ValueError("path must be non-empty repository-relative string")
    path = (root / rel).resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes repository root") from exc
    return path


def chain_descriptor(obj: dict[str, Any]) -> dict[str, Any]:
    replay = obj["replay"]
    return {"components": obj["components"], "keys": obj["keys"], "replayOrder": replay["order"],
            "subjectName": replay["subjectName"], "checkers": replay["checkers"]}


def run_json_command(command: list[str], cwd: Path):
    try:
        cp = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        return 127, None, str(exc)
    stderr = cp.stderr.decode("utf-8", errors="replace").strip()
    try:
        payload = strict_json_loads(cp.stdout, "P1A4.SUBPROCESS.JSON")
    except ValueError:
        payload = None
    return cp.returncode, payload if isinstance(payload, dict) else None, stderr


def run_bytes_command(command: list[str], cwd: Path):
    try:
        cp = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        return 127, b"", str(exc)
    return cp.returncode, cp.stdout, cp.stderr.decode("utf-8", errors="replace").strip()


def stage_codes(payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return ""
    return ",".join(sorted(item.get("code", "") for item in payload.get("findings", [])
                           if isinstance(item, dict) and isinstance(item.get("code"), str) and item.get("code")))


def result(findings: list[Finding], stages: dict[str, str], chain_id=None) -> dict[str, Any]:
    failed = bool(findings)
    return {
        "tool": "eigiib-interop-chain", "tool_version": TOOL_VERSION, "standard": STANDARD,
        "structural_result": "non-conformant" if failed else "conformant",
        "manifest_binding_result": stages.get("manifest", "not-evaluated"),
        "p1a1_replay_result": stages.get("p1a1", "not-evaluated"),
        "p1a2_replay_result": stages.get("p1a2", "not-evaluated"),
        "p1a3_replay_result": stages.get("p1a3", "not-evaluated"),
        "cross_capsule_binding_result": stages.get("cross", "not-evaluated"),
        "end_to_end_result": "non-conformant" if failed else "conformant",
        "chain_identity": chain_id,
        "trust_result": "not-evaluated-by-p1-a4",
        "production_interoperability_result": "not-evaluated-by-p1-a4",
        "findings": [asdict(f) for f in sorted(findings)],
    }
