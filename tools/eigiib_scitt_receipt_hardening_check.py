#!/usr/bin/env python3
"""P1-A3 H0.2: require full P1-A2 authentication before SCITT verification."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import eigiib_scitt_receipt as p1a3
import eigiib_sigstore_bundle as p1a2

TOOL_VERSION = "0.2.0"
STANDARD = "EIGIIB-P1-A3-hardening-0.2"


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def result(findings: list[Finding], upstream: str, baseline: str) -> dict[str, Any]:
    return {
        "tool": "eigiib-scitt-receipt-hardening-check",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "hardening_result": "non-conformant" if findings else "conformant",
        "upstream_p1a2_authentication_result": upstream,
        "p1a3_baseline_result": baseline,
        "findings": [asdict(f) for f in sorted(findings)],
    }


def validate_hardened(
    p1a3_obj: Any,
    p1a2_raw: bytes,
    p1a1_raw: bytes,
    p1a2_public_key: Path,
    issuer_public_key: Path,
    ts_public_key: Path,
    openssl: str = "openssl",
) -> dict[str, Any]:
    findings: list[Finding] = []

    try:
        p1a2_obj = p1a2.strict_json_loads(p1a2_raw, "P1A3H.UPSTREAM.P1A2")
        upstream = p1a2.validate_capsule(p1a2_obj, p1a2_public_key, p1a1_raw, openssl)
    except Exception as exc:
        findings.append(Finding("error", "P1A3H.UPSTREAM.ERROR", "P1-A2", str(exc)))
        return result(findings, "invalid", "not-evaluated")

    if upstream.get("structural_result") != "conformant" or upstream.get("signature_result") != "valid":
        codes = sorted(
            f.get("code", "")
            for f in upstream.get("findings", [])
            if isinstance(f, dict) and isinstance(f.get("code"), str)
        )
        findings.append(Finding(
            "error",
            "P1A3H.UPSTREAM.INVALID",
            "P1-A2",
            "upstream P1-A2 must be structurally conformant and signature-valid"
            + (f"; findings={','.join(codes)}" if codes else ""),
        ))
        return result(findings, "invalid", "not-evaluated")

    baseline = p1a3.validate_capsule(
        p1a3_obj,
        p1a2_raw,
        issuer_public_key,
        ts_public_key,
        openssl,
    )
    if baseline.get("structural_result") != "conformant" or baseline.get("registration_evidence_result") != "receipt-bound":
        codes = sorted(
            f.get("code", "")
            for f in baseline.get("findings", [])
            if isinstance(f, dict) and isinstance(f.get("code"), str)
        )
        findings.append(Finding(
            "error",
            "P1A3H.BASELINE.INVALID",
            "P1-A3",
            "P1-A3 baseline must be conformant with receipt-bound registration evidence"
            + (f"; findings={','.join(codes)}" if codes else ""),
        ))
        return result(findings, "valid", "invalid")

    return result([], "valid", "conformant")


def check_repository(root: Path, openssl: str = "openssl") -> dict[str, Any]:
    paths = {
        "p1a3": root / "tests/fixtures/p1-a3/capsule.json",
        "p1a2": root / "tests/fixtures/p1-a2/bundle.json",
        "p1a1": root / "tests/fixtures/p1-a1/capsule.json",
        "p1a2_key": root / "tests/fixtures/p1-a2/public-key.pem",
        "issuer_key": root / "tests/fixtures/p1-a3/issuer-public-key.pem",
        "ts_key": root / "tests/fixtures/p1-a3/ts-public-key.pem",
    }
    missing = [str(p) for p in paths.values() if not p.is_file()]
    if missing:
        return result(
            [Finding("error", "P1A3H.REPO.MISSING", ",".join(missing), "required hardening fixture dependency is missing")],
            "not-evaluated",
            "not-evaluated",
        )
    try:
        p1a3_obj = p1a3.strict_json_loads(paths["p1a3"].read_bytes(), "P1A3H.REPO.P1A3")
        return validate_hardened(
            p1a3_obj,
            paths["p1a2"].read_bytes(),
            paths["p1a1"].read_bytes(),
            paths["p1a2_key"],
            paths["issuer_key"],
            paths["ts_key"],
            openssl,
        )
    except Exception as exc:
        return result([Finding("error", "P1A3H.REPO.ERROR", str(root), str(exc))], "not-evaluated", "not-evaluated")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify")
    v.add_argument("capsule", type=Path)
    v.add_argument("--p1-a2", required=True, type=Path)
    v.add_argument("--p1-a1", required=True, type=Path)
    v.add_argument("--p1-a2-key", required=True, type=Path)
    v.add_argument("--issuer-key", required=True, type=Path)
    v.add_argument("--ts-key", required=True, type=Path)
    v.add_argument("--openssl", default="openssl")
    v.add_argument("--json", action="store_true")

    c = sub.add_parser("check")
    c.add_argument("root", nargs="?", type=Path, default=Path("."))
    c.add_argument("--openssl", default="openssl")
    c.add_argument("--json", action="store_true")

    args = parser.parse_args()
    if args.command == "verify":
        try:
            obj = p1a3.strict_json_loads(args.capsule.read_bytes(), "P1A3H.CLI.P1A3")
            out = validate_hardened(
                obj,
                args.p1_a2.read_bytes(),
                args.p1_a1.read_bytes(),
                args.p1_a2_key,
                args.issuer_key,
                args.ts_key,
                args.openssl,
            )
        except Exception as exc:
            out = result([Finding("error", "P1A3H.CLI", str(args.capsule), str(exc))], "not-evaluated", "not-evaluated")
    else:
        out = check_repository(args.root, args.openssl)

    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(out["hardening_result"])
        for finding in out["findings"]:
            print(f"{finding['severity']}: {finding['code']}: {finding['path']}: {finding['message']}")
    return 0 if out["hardening_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
