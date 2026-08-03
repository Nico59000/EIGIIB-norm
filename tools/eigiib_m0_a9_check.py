#!/usr/bin/env python3
"""Validate M0-A9 cross-lineage capability reconciliation without external dependencies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "conformance/m0-a9-cross-lineage-capabilities.json"
READINESS = ROOT / "conformance/m0-a9-promotion-readiness.json"
M0_A8 = ROOT / "conformance/m0-a8-lineage-publication.json"
M0_A5 = ROOT / "conformance/m0-a5-p1-lineage.json"

EXPECTED_M0_A8_HEAD = "232e8574f23fb2162a6fdf7fa24338e7aaf987d6"
EXPECTED_STABLE_E16_HEAD = "fc3f8402bfbe447227f5777bad92b620c7bcb350"
EXPECTED_PROFILE = "EIGIIB-E16-1.0"
EXPECTED_IDS = ["P1-A15", "P1-A16", "P1-A17", "P1-A18", "P1-A19", "P1-A19-F2", "P1-A20"]


class ConformanceError(RuntimeError):
    pass


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConformanceError(f"{path} must contain one object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


def validate(root: Path = ROOT) -> dict[str, Any]:
    authority = load(root / AUTHORITY.relative_to(ROOT))
    readiness = load(root / READINESS.relative_to(ROOT))
    m0_a8 = load(root / M0_A8.relative_to(ROOT))
    m0_a5 = load(root / M0_A5.relative_to(ROOT))

    require(authority.get("standard") == "EIGIIB-M0-A9-CROSS-LINEAGE-RECONCILIATION-1.0", "wrong M0-A9 standard")
    require(authority.get("status") == "cross-lineage-capability-boundaries-reconciled", "wrong M0-A9 status")

    source = authority.get("source", {})
    require(source.get("m0_a8_head") == EXPECTED_M0_A8_HEAD, "M0-A8 source head substitution")
    require(source.get("stable_e16_head") == EXPECTED_STABLE_E16_HEAD, "stable E16 head substitution")
    require(source.get("profile_revision") == EXPECTED_PROFILE, "profile revision mutation")
    require(m0_a8.get("standard") == "EIGIIB-M0-A8-LINEAGE-PUBLICATION-1.0", "wrong M0-A8 authority")
    require(m0_a8.get("status") == "lineage-publication-normalized", "M0-A8 is not closed")
    require(m0_a8.get("source_lineage", {}).get("head_commit") == EXPECTED_STABLE_E16_HEAD, "M0-A8 E16 source mismatch")
    require(m0_a8.get("source_lineage", {}).get("profile_revision") == EXPECTED_PROFILE, "M0-A8 profile mismatch")

    governance = authority.get("governance", {})
    require(governance.get("authority_mode") == "reference-not-copy", "P1 proof content must not be copied")
    for key in ("historical_heads_rewritten", "profile_mutated", "extension_graph_mutated", "e17_adopted", "automatic_cross_lineage_promotion"):
        require(governance.get(key) is False, f"{key} must remain false")
    require(governance.get("unknown_claim_boundary") == "deny", "unknown claim boundary must deny")

    classes = authority.get("claim_classes")
    require(isinstance(classes, list) and [x.get("id") for x in classes] == [
        "established-bounded", "declared-policy-only", "observed-current", "promotion-candidate", "not-established"
    ], "claim class order or membership changed")

    lineage = {item.get("id"): item for item in m0_a5.get("slices", []) if isinstance(item, dict)}
    capabilities = authority.get("capabilities")
    require(isinstance(capabilities, list), "capabilities must be an array")
    require([item.get("id") for item in capabilities] == EXPECTED_IDS, "capability set or order changed")
    for item in capabilities:
        cid = item["id"]
        source_state = load(root / item["state"])
        require(source_state.get("standard") == item.get("expected_standard"), f"{cid} standard mismatch")
        require(source_state.get("boundary") == item.get("expected_boundary"), f"{cid} boundary mismatch")
        require(source_state.get("overallResult", source_state.get("decisions", {}).get("overall_result")) == "conformant", f"{cid} is not conformant")
        require(cid in lineage, f"{cid} missing from M0-A5 lineage")
        require(lineage[cid].get("head_commit") == item.get("head_commit"), f"{cid} head mismatch")
        require(lineage[cid].get("state") == item.get("state"), f"{cid} state path mismatch")
        require(item.get("established") and item.get("promotion_targets") and item.get("forbidden_inferences"), f"{cid} boundary lists incomplete")

    indexed_targets = [item.get("target") for item in authority.get("cross_extension_index", [])]
    require(indexed_targets == ["E15", "E16"], "cross-extension index changed")
    for item in authority["cross_extension_index"]:
        require(item.get("requires_new_operation") is True, f"{item.get('target')} must require a new operation")
        require(item.get("forbidden"), f"{item.get('target')} forbidden inference list missing")

    required_nonclaims = {
        "e17-adoption", "new-live-external-publication", "continuous-retention",
        "indefinite-durability", "real-custodian-or-provider-independence",
        "correlated-failure-resistance", "universal-interoperability",
        "automatic-promotion-of-p1-results-into-e15-or-e16"
    }
    require(required_nonclaims.issubset(set(authority.get("nonclaims", []))), "required nonclaims missing")

    require(readiness.get("standard") == "EIGIIB-M0-A9-PROMOTION-READINESS-1.0", "wrong readiness standard")
    require(readiness.get("profile_revision") == EXPECTED_PROFILE, "readiness profile mutation")
    require(readiness.get("automatic_adoption") is False, "automatic adoption forbidden")
    candidates = {item.get("id"): item for item in readiness.get("candidates", [])}
    require(candidates.get("M0-A10", {}).get("decision") == "ready-for-bounded-implementation", "M0-A10 readiness changed")
    require(len(candidates["M0-A10"].get("required_new_operations", [])) == 6, "M0-A10 operation set incomplete")
    require(candidates.get("E17", {}).get("decision") == "not-ready-for-adoption", "premature E17 adoption")
    require(len(candidates["E17"].get("missing_evidence", [])) == 5, "E17 missing-evidence set incomplete")

    return {
        "standard": "EIGIIB-M0-A9-REPORT-1.0",
        "result": "cross-lineage-capability-boundaries-reconciled",
        "source_m0_a8_head": EXPECTED_M0_A8_HEAD,
        "stable_e16_head": EXPECTED_STABLE_E16_HEAD,
        "profile_revision": EXPECTED_PROFILE,
        "capability_count": len(capabilities),
        "verified_capabilities": EXPECTED_IDS,
        "claim_class_count": len(classes),
        "promotion_ready": ["M0-A10"],
        "promotion_blocked": ["E17"],
        "e17_adopted": False
    }


def canonical_bytes(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = validate(args.root.resolve())
    except ConformanceError as exc:
        print(f"M0-A9: FAIL: {exc}")
        return 1
    payload = canonical_bytes(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(payload.decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
