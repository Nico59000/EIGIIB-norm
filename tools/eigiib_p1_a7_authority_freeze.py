#!/usr/bin/env python3
"""Freeze and attest the complete P1-A7 portable negative corpus authority."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from eigiib_p1_a7_authority_common import PLATFORMS, canonical_json_bytes, content_root, load_json
from eigiib_p1_a7_authority_inventory import build_report, validate_manifest, validate_prior_reports
from eigiib_p1_a7_authority_platform import validate_toolchain


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--attestation-out", required=True, type=Path)
    parser.add_argument("--require-git-source", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        manifest = load_json(args.manifest, "A7.7 authority manifest")
        policy = load_json(args.policy, "A7.7 toolchain policy")
        expected = load_json(args.expected, "A7.7 expected report")
        if not isinstance(manifest, dict) or not isinstance(policy, dict) or not isinstance(expected, dict):
            raise ValueError("A7.7 top-level carriers must be objects")
        rows = validate_manifest(root, manifest, args.require_git_source)
        validate_prior_reports(root, manifest)
        versions, platform_rows = validate_toolchain(root, policy, args.platform)
        report = build_report(manifest)
        if canonical_json_bytes(report) != canonical_json_bytes(expected):
            raise ValueError("canonical A7.7 authority report differs")
        attestation = {
            "standard": "EIGIIB-P1-A7.7-PLATFORM-1.0",
            "platform": args.platform,
            "authority_root": manifest["authorityRoot"]["digest"],
            "content_sha256_root": content_root(rows),
            "runner": platform_rows["runner"],
            "toolchain": versions,
            "executables": platform_rows["executables"],
            "result": "conformant",
        }
        args.attestation_out.write_bytes(canonical_json_bytes(attestation))
        output = report if args.json else {
            "overall_result": report["overall_result"],
            "authority_root": report["authority_root"],
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A7.7.AUTHORITY.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
