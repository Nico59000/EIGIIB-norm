#!/usr/bin/env python3
"""Replay P1-A13 through Python, independent Go and external go-cose routes."""
from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path
from typing import Any
from eigiib_p1_a13_common import ROUTES, strict_json
from eigiib_p1_a13_revocation_check import evaluate

PROJECTION = [
    "release_id", "release_descriptor_sha256", "content_archive_sha256",
    "source_transparency_report_sha256", "source_transparency_capsule_sha256",
    "trusted_effective_time_unix", "policy_envelope_sha256", "revocation_envelope_sha256",
    "revocation_sequence", "registered_channel_ids", "withdrawn_channel_ids",
    "accepted_history", "replay_results", "content_revocation_result",
    "distribution_withdrawal_result", "anti_rollback_result",
    "global_content_unavailability_result", "vulnerability_remediation_result",
    "boundary", "overall_result",
]

def _go(root: Path, module: str, go: str, capsule: Path) -> dict[str, Any]:
    command = [go, "run", "./cmd/eigiib-p1-revocation-adapter", "--root", str(root), "--capsule", str(capsule)]
    result = subprocess.run(command, cwd=root / module, check=True, capture_output=True)
    value = strict_json(result.stdout)
    if not isinstance(value, dict):
        raise ValueError(f"{module} result")
    return value

def replay(root: Path, capsule: Path, go: str = "go", openssl: str = "openssl") -> dict[str, Any]:
    results = {
        "reference-python-openssl": evaluate(root, capsule, openssl),
        "independent-go-stdlib": _go(root, "independent", go, capsule),
        "external-go-cose": _go(root, "external", go, capsule),
    }
    baseline = results[ROUTES[0]]
    for route in ROUTES[1:]:
        if results[route] != baseline:
            raise ValueError(f"route mismatch: {route}")
    projection = {key: baseline[key] for key in PROJECTION}
    return {
        "overall_result": "conformant",
        "portable_projection": projection,
        "routes": [{"route": route, "result": results[route]} for route in ROUTES],
        "standard": "EIGIIB-P1-A13-REPLAY-1.0",
    }

def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("root",type=Path)
    parser.add_argument("--capsule",type=Path,default=Path("tests/fixtures/p1-a13/capsule.json"))
    parser.add_argument("--expected",type=Path)
    parser.add_argument("--go",default="go")
    parser.add_argument("--openssl",default="openssl")
    parser.add_argument("--json",action="store_true")
    args=parser.parse_args()
    try:
        root=args.root.resolve(); capsule=args.capsule if args.capsule.is_absolute() else root/args.capsule
        result=replay(root,capsule,args.go,args.openssl)
        if args.expected:
            p=args.expected if args.expected.is_absolute() else root/args.expected
            if result!=strict_json(p.read_bytes()): raise ValueError("expected replay mismatch")
        print(json.dumps(result,sort_keys=True,separators=(",",":")) if args.json else result["overall_result"])
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.CalledProcessError) as exc:
        print(json.dumps({"overall_result":"non-conformant","error":str(exc)},sort_keys=True,separators=(",",":")) if args.json else f"non-conformant: {exc}", file=sys.stderr)
        return 1
if __name__=="__main__": raise SystemExit(main())
