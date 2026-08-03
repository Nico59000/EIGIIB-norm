#!/usr/bin/env python3
"""Validate M0-A8 lineage publication and pull-request topology."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

TOOL = "eigiib-m0-a8-check"
TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-M0-A8-LINEAGE-PUBLICATION-1.0"
AUTHORITY_PATH = Path("conformance/m0-a8-lineage-publication.json")
E16_CLOSURE_PATH = Path("conformance/e16-final-closure.json")
E16_FREEZE_PATH = Path("conformance/e16-a5-authority-freeze.json")
M0_A8_FREEZE_PATH = Path("conformance/m0-a8-authority-freeze.json")
SOURCE_BRANCH = "agent/e16-a5-independent-preservation-verifier-matrix-differential-restore-replay-final-freeze"
SOURCE_HEAD = "fc3f8402bfbe447227f5777bad92b620c7bcb350"
STABLE_BRANCH = "stable/eigiib-e16-1.0"
M0_A8_BRANCH = "agent/m0-a8-authoritative-lineage-publication-default-branch-reconciliation-pr-topology-closure"
DEFAULT_BRANCH = "main"
DEFAULT_HEAD = "b0f4ec77000c0d4dd49915d78d0ab23946da4031"
EXPECTED_CLOSED_PRS = [141, 145, 147, 155]
EXPECTED_LINEAGE_IDS = [
    "M0-A5-F1", "E14-A1", "E14-A2", "E14-A3", "E14-A4", "E14-A5",
    "E14-A5-F1", "M0-A6", "E15-A1", "E15-A2", "E15-A3", "E15-A4",
    "E15-A5", "M0-A7", "E16-A1", "E16-A2", "E16-A3", "E16-A4", "E16-A5",
]


def _load_json(path: Path, findings: list[dict[str, str]], code: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        findings.append({"code": f"{code}.MISSING", "path": path.as_posix(), "message": "required JSON file is missing"})
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        findings.append({"code": f"{code}.INVALID", "path": path.as_posix(), "message": str(exc)})
    return None


def _expect(findings: list[dict[str, str]], condition: bool, code: str, path: str, message: str) -> None:
    if not condition:
        findings.append({"code": code, "path": path, "message": message})


def _check_authority(root: Path, findings: list[dict[str, str]]) -> dict[str, Any] | None:
    authority = _load_json(root / AUTHORITY_PATH, findings, "M0A8.AUTHORITY")
    if not isinstance(authority, dict):
        return None

    _expect(findings, authority.get("standard") == STANDARD, "M0A8.STANDARD", AUTHORITY_PATH.as_posix(), "unexpected standard")
    _expect(findings, authority.get("status") == "lineage-publication-normalized", "M0A8.STATUS", AUTHORITY_PATH.as_posix(), "unexpected status")

    source = authority.get("source_lineage")
    _expect(findings, isinstance(source, dict), "M0A8.SOURCE.TYPE", AUTHORITY_PATH.as_posix(), "source_lineage must be an object")
    if isinstance(source, dict):
        _expect(findings, source.get("branch") == SOURCE_BRANCH, "M0A8.SOURCE.BRANCH", AUTHORITY_PATH.as_posix(), "source branch changed")
        _expect(findings, source.get("head_commit") == SOURCE_HEAD, "M0A8.SOURCE.HEAD", AUTHORITY_PATH.as_posix(), "source head changed")
        _expect(findings, source.get("profile_revision") == "EIGIIB-E16-1.0", "M0A8.SOURCE.PROFILE", AUTHORITY_PATH.as_posix(), "source profile changed")
        _expect(findings, source.get("pull_request") == 153, "M0A8.SOURCE.PR", AUTHORITY_PATH.as_posix(), "source PR changed")
        _expect(findings, source.get("frozen_authority_count") == 95, "M0A8.SOURCE.COUNT", AUTHORITY_PATH.as_posix(), "source authority count changed")

    roles = authority.get("publication_roles")
    _expect(findings, isinstance(roles, dict), "M0A8.ROLES.TYPE", AUTHORITY_PATH.as_posix(), "publication_roles must be an object")
    if isinstance(roles, dict):
        default = roles.get("default_branch")
        stable = roles.get("stable_normative_branch")
        successor = roles.get("governance_successor_branch")
        _expect(findings, isinstance(default, dict), "M0A8.DEFAULT.TYPE", AUTHORITY_PATH.as_posix(), "default branch role missing")
        _expect(findings, isinstance(stable, dict), "M0A8.STABLE.TYPE", AUTHORITY_PATH.as_posix(), "stable branch role missing")
        _expect(findings, isinstance(successor, dict), "M0A8.SUCCESSOR.TYPE", AUTHORITY_PATH.as_posix(), "successor branch role missing")
        if isinstance(default, dict):
            _expect(findings, default.get("name") == DEFAULT_BRANCH, "M0A8.DEFAULT.NAME", AUTHORITY_PATH.as_posix(), "default branch changed")
            _expect(findings, default.get("observed_head") == DEFAULT_HEAD, "M0A8.DEFAULT.HEAD", AUTHORITY_PATH.as_posix(), "default head changed")
            _expect(findings, default.get("role") == "legacy-default-not-current-normative-lineage", "M0A8.DEFAULT.ROLE", AUTHORITY_PATH.as_posix(), "default role changed")
        if isinstance(stable, dict):
            _expect(findings, stable.get("name") == STABLE_BRANCH, "M0A8.STABLE.NAME", AUTHORITY_PATH.as_posix(), "stable branch changed")
            _expect(findings, stable.get("head_commit") == SOURCE_HEAD, "M0A8.STABLE.HEAD", AUTHORITY_PATH.as_posix(), "stable head changed")
            _expect(findings, stable.get("role") == "published-stable-normative-lineage", "M0A8.STABLE.ROLE", AUTHORITY_PATH.as_posix(), "stable role changed")
        if isinstance(successor, dict):
            _expect(findings, successor.get("name") == M0_A8_BRANCH, "M0A8.SUCCESSOR.NAME", AUTHORITY_PATH.as_posix(), "successor branch changed")
            _expect(findings, successor.get("base_branch") == SOURCE_BRANCH, "M0A8.SUCCESSOR.BASE", AUTHORITY_PATH.as_posix(), "successor base changed")
            _expect(findings, successor.get("base_head") == SOURCE_HEAD, "M0A8.SUCCESSOR.HEAD", AUTHORITY_PATH.as_posix(), "successor base head changed")

    reconciliation = authority.get("reconciliation")
    expected_reconciliation = {
        "default_branch_moved": False,
        "historical_heads_rewritten": False,
        "stable_publication_created": True,
        "main_merge_authorized": False,
        "resolution": "separate-default-and-normative-publication-roles",
    }
    _expect(findings, reconciliation == expected_reconciliation, "M0A8.RECONCILIATION", AUTHORITY_PATH.as_posix(), "reconciliation contract changed")

    topology = authority.get("authoritative_pr_topology")
    _expect(findings, isinstance(topology, list), "M0A8.TOPOLOGY.TYPE", AUTHORITY_PATH.as_posix(), "authoritative_pr_topology must be an array")
    if isinstance(topology, list):
        ids = [item.get("id") for item in topology if isinstance(item, dict)]
        _expect(findings, ids == EXPECTED_LINEAGE_IDS, "M0A8.TOPOLOGY.ORDER", AUTHORITY_PATH.as_posix(), "lineage order changed")
        previous_head: str | None = None
        for index, item in enumerate(topology):
            if not isinstance(item, dict):
                findings.append({"code": "M0A8.TOPOLOGY.ITEM", "path": AUTHORITY_PATH.as_posix(), "message": f"topology item {index} is not an object"})
                continue
            head = item.get("head")
            base_head = item.get("base_head")
            _expect(findings, isinstance(item.get("pull_request"), int) and item["pull_request"] > 0, "M0A8.TOPOLOGY.PR", AUTHORITY_PATH.as_posix(), f"invalid pull request for item {index}")
            _expect(findings, isinstance(head, str) and len(head) == 40, "M0A8.TOPOLOGY.HEAD", AUTHORITY_PATH.as_posix(), f"invalid head for item {index}")
            _expect(findings, isinstance(base_head, str) and len(base_head) == 40, "M0A8.TOPOLOGY.BASE", AUTHORITY_PATH.as_posix(), f"invalid base for item {index}")
            if previous_head is not None:
                _expect(findings, base_head == previous_head, "M0A8.TOPOLOGY.CHAIN", AUTHORITY_PATH.as_posix(), f"non-contiguous lineage at item {index}")
            previous_head = head if isinstance(head, str) else previous_head
        if topology:
            _expect(findings, topology[-1].get("head") == SOURCE_HEAD, "M0A8.TOPOLOGY.TERMINAL", AUTHORITY_PATH.as_posix(), "terminal head is not E16-A5")

    _expect(findings, authority.get("closed_non_authoritative_prs") == EXPECTED_CLOSED_PRS, "M0A8.CLOSED_PRS", AUTHORITY_PATH.as_posix(), "closed PR set changed")

    policy = authority.get("pr_topology_policy")
    _expect(findings, isinstance(policy, dict), "M0A8.POLICY.TYPE", AUTHORITY_PATH.as_posix(), "pr_topology_policy must be an object")
    if isinstance(policy, dict):
        _expect(findings, policy.get("default_branch") == DEFAULT_BRANCH, "M0A8.POLICY.DEFAULT", AUTHORITY_PATH.as_posix(), "policy default branch changed")
        _expect(findings, policy.get("forbidden_direct_head_prefixes") == ["agent/"], "M0A8.POLICY.PREFIXES", AUTHORITY_PATH.as_posix(), "forbidden prefixes changed")
        _expect(findings, policy.get("authorized_default_branch_heads") == [], "M0A8.POLICY.EXCEPTIONS", AUTHORITY_PATH.as_posix(), "unexpected direct-to-default exception")
        _expect(findings, policy.get("unknown_direct_to_default_state") == "deny", "M0A8.POLICY.UNKNOWN", AUTHORITY_PATH.as_posix(), "unknown direct state must deny")

    supersession = authority.get("historical_status_supersession")
    _expect(findings, isinstance(supersession, list) and len(supersession) == 1, "M0A8.SUPERSESSION.TYPE", AUTHORITY_PATH.as_posix(), "one status supersession is required")
    if isinstance(supersession, list) and len(supersession) == 1 and isinstance(supersession[0], dict):
        item = supersession[0]
        _expect(findings, item.get("current_status") == "closed-at-e15-a5-profile-eigiib-e15-1.0", "M0A8.SUPERSESSION.STATUS", AUTHORITY_PATH.as_posix(), "E15 current status changed")
        _expect(findings, item.get("historical_file_rewritten") is False, "M0A8.SUPERSESSION.REWRITE", AUTHORITY_PATH.as_posix(), "historical E15 file must remain unchanged")

    freeze_meta = authority.get("authority_freeze")
    _expect(findings, freeze_meta == {"path": M0_A8_FREEZE_PATH.as_posix(), "status": "self-excluding", "authority_count": 9}, "M0A8.FREEZE.META", AUTHORITY_PATH.as_posix(), "M0-A8 freeze metadata changed")

    gate = authority.get("manual_gate")
    _expect(findings, gate == {"status": "complete", "attestation": "conformance/M0-A8-MANUAL-REVIEW.md"}, "M0A8.MANUAL", AUTHORITY_PATH.as_posix(), "manual gate incomplete")
    return authority


def _check_source_closure(root: Path, findings: list[dict[str, str]]) -> None:
    closure = _load_json(root / E16_CLOSURE_PATH, findings, "M0A8.E16.CLOSURE")
    if isinstance(closure, dict):
        _expect(findings, closure.get("standard") == "EIGIIB-E16-A5-CLOSURE-1.0", "M0A8.E16.CLOSURE.STANDARD", E16_CLOSURE_PATH.as_posix(), "unexpected E16 closure standard")
        _expect(findings, closure.get("status") == "final-frozen-closure", "M0A8.E16.CLOSURE.STATUS", E16_CLOSURE_PATH.as_posix(), "E16 closure is not final frozen")
        _expect(findings, closure.get("final_state") == "closed", "M0A8.E16.CLOSURE.STATE", E16_CLOSURE_PATH.as_posix(), "E16 is not closed")
        _expect(findings, closure.get("profile_revision") == "EIGIIB-E16-1.0", "M0A8.E16.CLOSURE.PROFILE", E16_CLOSURE_PATH.as_posix(), "E16 profile changed")
        _expect(findings, closure.get("expected_authority_count") == 95, "M0A8.E16.CLOSURE.COUNT", E16_CLOSURE_PATH.as_posix(), "E16 closure count changed")

    freeze = _load_json(root / E16_FREEZE_PATH, findings, "M0A8.E16.FREEZE")
    if isinstance(freeze, dict):
        _expect(findings, freeze.get("standard") == "EIGIIB-E16-A5-FREEZE-1.0", "M0A8.E16.FREEZE.STANDARD", E16_FREEZE_PATH.as_posix(), "unexpected E16 freeze standard")
        _expect(findings, freeze.get("status") == "final-frozen", "M0A8.E16.FREEZE.STATUS", E16_FREEZE_PATH.as_posix(), "E16 freeze is not final")
        _expect(findings, freeze.get("profile_revision") == "EIGIIB-E16-1.0", "M0A8.E16.FREEZE.PROFILE", E16_FREEZE_PATH.as_posix(), "E16 freeze profile changed")
        authorities = freeze.get("authorities")
        _expect(findings, freeze.get("authority_count") == 95, "M0A8.E16.FREEZE.COUNT", E16_FREEZE_PATH.as_posix(), "E16 freeze count changed")
        _expect(findings, isinstance(authorities, list) and len(authorities) == 95, "M0A8.E16.FREEZE.ARRAY", E16_FREEZE_PATH.as_posix(), "E16 frozen authority array changed")


def _check_m0_a8_freeze(root: Path, findings: list[dict[str, str]]) -> None:
    freeze = _load_json(root / M0_A8_FREEZE_PATH, findings, "M0A8.FREEZE")
    if not isinstance(freeze, dict):
        return
    _expect(findings, freeze.get("standard") == "EIGIIB-M0-A8-FREEZE-1.0", "M0A8.FREEZE.STANDARD", M0_A8_FREEZE_PATH.as_posix(), "unexpected M0-A8 freeze standard")
    _expect(findings, freeze.get("status") == "frozen", "M0A8.FREEZE.STATUS", M0_A8_FREEZE_PATH.as_posix(), "M0-A8 freeze is not frozen")
    _expect(findings, freeze.get("source_head") == SOURCE_HEAD, "M0A8.FREEZE.SOURCE", M0_A8_FREEZE_PATH.as_posix(), "M0-A8 freeze source changed")
    authorities = freeze.get("authorities")
    _expect(findings, freeze.get("authority_count") == 9, "M0A8.FREEZE.COUNT", M0_A8_FREEZE_PATH.as_posix(), "M0-A8 freeze count changed")
    if not isinstance(authorities, list):
        findings.append({"code": "M0A8.FREEZE.ARRAY", "path": M0_A8_FREEZE_PATH.as_posix(), "message": "authorities must be an array"})
        return
    _expect(findings, len(authorities) == 9, "M0A8.FREEZE.LENGTH", M0_A8_FREEZE_PATH.as_posix(), "M0-A8 freeze length changed")
    paths = [item.get("path") for item in authorities if isinstance(item, dict)]
    _expect(findings, len(paths) == len(set(paths)), "M0A8.FREEZE.DUPLICATE", M0_A8_FREEZE_PATH.as_posix(), "duplicate frozen path")
    _expect(findings, M0_A8_FREEZE_PATH.as_posix() not in paths, "M0A8.FREEZE.SELF", M0_A8_FREEZE_PATH.as_posix(), "freeze must exclude itself")
    import hashlib
    for item in authorities:
        if not isinstance(item, dict):
            findings.append({"code": "M0A8.FREEZE.ITEM", "path": M0_A8_FREEZE_PATH.as_posix(), "message": "invalid freeze item"})
            continue
        path = item.get("path")
        if not isinstance(path, str):
            findings.append({"code": "M0A8.FREEZE.PATH", "path": M0_A8_FREEZE_PATH.as_posix(), "message": "invalid frozen path"})
            continue
        target = root / path
        try:
            raw = target.read_bytes()
        except OSError as exc:
            findings.append({"code": "M0A8.FREEZE.MISSING", "path": path, "message": str(exc)})
            continue
        _expect(findings, item.get("bytes") == len(raw), "M0A8.FREEZE.BYTES", path, "frozen byte count mismatch")
        _expect(findings, item.get("sha256") == hashlib.sha256(raw).hexdigest(), "M0A8.FREEZE.DIGEST", path, "frozen digest mismatch")


def _check_event(authority: dict[str, Any], event: dict[str, Any], findings: list[dict[str, str]]) -> None:
    pull = event.get("pull_request")
    if not isinstance(pull, dict):
        return
    base = pull.get("base") if isinstance(pull.get("base"), dict) else {}
    head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
    base_ref = base.get("ref")
    base_sha = base.get("sha")
    head_ref = head.get("ref")

    policy = authority.get("pr_topology_policy") if isinstance(authority.get("pr_topology_policy"), dict) else {}
    forbidden = policy.get("forbidden_direct_head_prefixes") if isinstance(policy.get("forbidden_direct_head_prefixes"), list) else []
    authorized = policy.get("authorized_default_branch_heads") if isinstance(policy.get("authorized_default_branch_heads"), list) else []
    if base_ref == DEFAULT_BRANCH and isinstance(head_ref, str):
        if any(head_ref.startswith(prefix) for prefix in forbidden) and head_ref not in authorized:
            findings.append({"code": "M0A8.EVENT.DIRECT_TO_DEFAULT", "path": "$GITHUB_EVENT_PATH", "message": f"non-authoritative direct-to-{DEFAULT_BRANCH} PR from {head_ref}"})

    if head_ref == M0_A8_BRANCH:
        _expect(findings, base_ref == SOURCE_BRANCH, "M0A8.EVENT.BASE_BRANCH", "$GITHUB_EVENT_PATH", "M0-A8 PR base branch changed")
        _expect(findings, base_sha == SOURCE_HEAD, "M0A8.EVENT.BASE_HEAD", "$GITHUB_EVENT_PATH", "M0-A8 PR base head changed")


def check(root: Path, event_path: Path | None = None) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    authority = _check_authority(root, findings)
    _check_source_closure(root, findings)
    _check_m0_a8_freeze(root, findings)
    if event_path is not None:
        event = _load_json(event_path, findings, "M0A8.EVENT")
        if isinstance(authority, dict) and isinstance(event, dict):
            _check_event(authority, event, findings)

    report = {
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "overall_result": "conformant" if not findings else "non-conformant",
        "source_head": SOURCE_HEAD,
        "stable_branch": STABLE_BRANCH,
        "default_branch": DEFAULT_BRANCH,
        "closed_non_authoritative_prs": EXPECTED_CLOSED_PRS,
        "finding_count": len(findings),
        "findings": findings,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--event", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = check(Path(args.root).resolve(), args.event)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["overall_result"])
        for finding in report["findings"]:
            print(f"{finding['code']}: {finding['message']}", file=sys.stderr)
    return 0 if report["overall_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
