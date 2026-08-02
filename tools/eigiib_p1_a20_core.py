from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A20-CONFORMANCE-1.0"
SOURCE_COMMIT = "66b25d4f27ded3e273922f9fdcf80b9c88c8c808"
SOURCE_REPORT_SHA256 = "8008f0eb90328a4ff01f1bd4a594f1f7417ecbd3f5c68efdcf07bf801be62c2a"
ENVIRONMENT = "p1-a20-fixture-production"
BOUNDARY = "signed-runner-admission-toolchain-succession-declared-compatibility-window-single-use-rollback-replay-closure"
FIXTURE = Path("tests/fixtures/p1-a20")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_bundle(index_path: Path | None = None) -> dict[str, Any]:
    index_path = index_path or FIXTURE / "bundle-index.json"
    base = index_path.parent
    index = load_json(index_path)
    return {
        "environment": index["environment"],
        "routes": [load_json(base / name) for name in index["routeFiles"]],
        "signedRollbackAuthorizations": [load_json(base / name) for name in index["rollbackAuthorizationFiles"]],
        "signedRunnerRegistry": load_json(base / index["runnerRegistryFile"]),
        "signedToolchainRegistry": load_json(base / index["toolchainRegistryFile"]),
        "sourceP1A19F2Commit": index["sourceP1A19F2Commit"],
        "sourceP1A19ReportSha256": index["sourceP1A19ReportSha256"],
        "standard": index["standard"],
    }


def verify_ed25519(public_key: Path, payload: Any, signature_b64: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        payload_path = Path(td) / "payload.json"
        signature_path = Path(td) / "signature.bin"
        payload_path.write_bytes(canonical_bytes(payload))
        signature_path.write_bytes(base64.b64decode(signature_b64, validate=True))
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key), "-rawin", "-in", str(payload_path), "-sigfile", str(signature_path)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise ValueError("signature verification failed")


def validate_source(payload: dict[str, Any]) -> None:
    if payload.get("standard") != STANDARD:
        raise ValueError("standard mismatch")
    if payload.get("sourceP1A19F2Commit") != SOURCE_COMMIT:
        raise ValueError("source commit mismatch")
    if payload.get("sourceP1A19ReportSha256") != SOURCE_REPORT_SHA256:
        raise ValueError("source report mismatch")
    if payload.get("environment") != ENVIRONMENT:
        raise ValueError("environment mismatch")
