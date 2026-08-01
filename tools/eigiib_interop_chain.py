#!/usr/bin/env python3
"""Verify the EIGIIB P1-A1 -> P1-A2 -> P1-A3 interoperability chain."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from eigiib_interop_chain_contract import *
from eigiib_interop_chain_validation import prepare_chain


def validate_chain(root: Path, manifest: Any, openssl="openssl",
                   json_runner: Callable = run_json_command,
                   bytes_runner: Callable = run_bytes_command):
    root = root.resolve()
    findings, stages, chain_id, paths = prepare_chain(root, manifest)
    if findings:
        return result(findings, stages, chain_id)
    python = sys.executable
    p1a1, p1a2, p1a3 = (CHECKER_CONTRACT[x][0] for x in REPLAY_ORDER)

    rc, rebuilt, stderr = bytes_runner([python, p1a1, "build", COMPONENT_PATHS["m0-a2-report"],
                                        "--subject-name", SUBJECT_NAME], root)
    if rc != 0 or rebuilt != paths["p1-a1-statement"].read_bytes():
        findings.append(Finding("error", "P1A4.REPLAY.P1A1_REBUILD", p1a1,
                                "P1-A1 deterministic rebuild differs from checked-in capsule" + (f"; stderr={stderr}" if stderr else "")))
        stages["p1a1"] = "invalid"
    else:
        rc, payload, stderr = json_runner([python, p1a1, "verify", COMPONENT_PATHS["p1-a1-statement"],
                                           "--source", COMPONENT_PATHS["m0-a2-report"], "--json"], root)
        if rc or not payload or payload.get("structural_result") != "conformant" or payload.get("tool_version") != CHECKER_CONTRACT["p1-a1"][1]:
            findings.append(Finding("error", "P1A4.REPLAY.P1A1", p1a1,
                                    "P1-A1 replay failed" + (f"; findings={stage_codes(payload)}" if payload else "") + (f"; stderr={stderr}" if stderr else "")))
            stages["p1a1"] = "invalid"
        else:
            stages["p1a1"] = "conformant"

    rc, payload, stderr = json_runner([python, p1a2, "verify", COMPONENT_PATHS["p1-a2-bundle"],
                                       "--public-key", KEY_CONTRACT["p1-a2-public-key"][0],
                                       "--p1-a1", COMPONENT_PATHS["p1-a1-statement"], "--openssl", openssl, "--json"], root)
    if rc or not payload or payload.get("structural_result") != "conformant" or payload.get("signature_result") != "valid" or payload.get("tool_version") != CHECKER_CONTRACT["p1-a2"][1]:
        findings.append(Finding("error", "P1A4.REPLAY.P1A2", p1a2,
                                "P1-A2 replay failed" + (f"; findings={stage_codes(payload)}" if payload else "") + (f"; stderr={stderr}" if stderr else "")))
        stages["p1a2"] = "invalid"
    else:
        stages["p1a2"] = "conformant"

    rc, payload, stderr = json_runner([python, p1a3, "verify", COMPONENT_PATHS["p1-a3-signed-statement"],
                                       "--p1-a2", COMPONENT_PATHS["p1-a2-bundle"], "--p1-a1", COMPONENT_PATHS["p1-a1-statement"],
                                       "--p1-a2-key", KEY_CONTRACT["p1-a2-public-key"][0], "--issuer-key", KEY_CONTRACT["p1-a3-issuer-key"][0],
                                       "--ts-key", KEY_CONTRACT["p1-a3-transparency-service-key"][0], "--openssl", openssl, "--json"], root)
    if rc or not payload or payload.get("hardening_result") != "conformant" or payload.get("upstream_p1a2_authentication_result") != "valid" or payload.get("p1a3_baseline_result") != "conformant" or payload.get("tool_version") != CHECKER_CONTRACT["p1-a3-h0.2"][1]:
        findings.append(Finding("error", "P1A4.REPLAY.P1A3", p1a3,
                                "P1-A3 hardened replay failed" + (f"; findings={stage_codes(payload)}" if payload else "") + (f"; stderr={stderr}" if stderr else "")))
        stages["p1a3"] = "invalid"
    else:
        stages["p1a3"] = "conformant"
    return result(findings, stages, chain_id)


def check_repository(root: Path, openssl="openssl", json_runner=run_json_command, bytes_runner=run_bytes_command):
    root = root.resolve()
    manifest_path = root / "tests/fixtures/p1-a4/chain.json"
    state_path = root / "conformance/p1-a4-chain.json"
    if not manifest_path.is_file():
        return result([Finding("error", "P1A4.REPO.MISSING", str(manifest_path), "chain manifest is missing")], {})
    try:
        manifest = strict_json_loads(manifest_path.read_bytes(), "P1A4.REPO.MANIFEST")
    except ValueError as exc:
        return result([Finding("error", "P1A4.REPO.PARSE", str(manifest_path), str(exc))], {})
    out = validate_chain(root, manifest, openssl, json_runner, bytes_runner)
    extra = []
    if not state_path.is_file():
        extra.append(Finding("error", "P1A4.REPO.STATE_MISSING", str(state_path), "structural state is missing"))
    else:
        try:
            state = strict_json_loads(state_path.read_bytes(), "P1A4.REPO.STATE")
            expected = {"standard": STANDARD, "status": "structural-only", "profile": PROFILE,
                        "chain_manifest": "tests/fixtures/p1-a4/chain.json",
                        "execution_scope": "fixed-repository-checkers-only", "network_mode": "none", "production_replays": []}
            if state != expected:
                extra.append(Finding("error", "P1A4.REPO.STATE", str(state_path), "structural state differs from P1-A4 contract"))
        except ValueError as exc:
            extra.append(Finding("error", "P1A4.REPO.STATE_PARSE", str(state_path), str(exc)))
    if not extra:
        return out
    merged = [Finding(**item) for item in out["findings"]] + extra
    stages = {"manifest": out["manifest_binding_result"], "p1a1": out["p1a1_replay_result"],
              "p1a2": out["p1a2_replay_result"], "p1a3": out["p1a3_replay_result"],
              "cross": out["cross_capsule_binding_result"]}
    return result(merged, stages, out.get("chain_identity"))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify")
    v.add_argument("manifest", type=Path); v.add_argument("--root", type=Path, default=Path(".")); v.add_argument("--openssl", default="openssl"); v.add_argument("--json", action="store_true")
    c = sub.add_parser("check")
    c.add_argument("root", nargs="?", type=Path, default=Path(".")); c.add_argument("--openssl", default="openssl"); c.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            out = validate_chain(args.root, strict_json_loads(args.manifest.read_bytes(), "P1A4.CLI.MANIFEST"), args.openssl)
        else:
            out = check_repository(args.root, args.openssl)
    except Exception as exc:
        out = result([Finding("error", "P1A4.CLI.ERROR", "", str(exc))], {})
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(out["end_to_end_result"])
        for f in out["findings"]:
            print(f"{f['severity']}: {f['code']}: {f['path']}: {f['message']}")
    return 0 if out["end_to_end_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
