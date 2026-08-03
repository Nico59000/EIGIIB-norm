#!/usr/bin/env python3
"""Validate M0-A7 E16 entry normalization without adopting E16."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tomllib
from typing import Any

TOOL = "eigiib-m0-a7-check"
TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-M0-A7-E16-ENTRY-1.0"
SOURCE_BRANCH = "agent/e15-a5-independent-external-evidence-verifier-final-freeze"
SOURCE_HEAD = "036b81c3c128524858d66d096a1eb87e23cc5dad"
SOURCE_PROFILE = "EIGIIB-E15-1.0"
HISTORY_RUN = 30811560795
FINAL_RUN = 30811560397
PLATFORMS = ["ubuntu-24.04", "macos-15", "windows-2025"]
TARGET_TITLE = "External Custody, Replication, Retention and Recovery Governance"
AUTHORITY_PATH = Path("conformance/m0-a7-e16-entry.json")
FREEZE_PATH = Path("conformance/e15-a5-authority-freeze.json")
FINAL_CLOSURE_PATH = Path("conformance/e15-final-closure.json")
MANUAL_PATH = Path("conformance/M0-A7-MANUAL-REVIEW.md")
GUIDE_PATH = Path("docs/M0-A7-HUMAN-MASTERY-GUIDE.md")
CONTRACT_PATH = Path("docs/M0-A7-E16-NORMATIVE-ENTRY-NORMALIZATION-AND-E15-AUTHORITY-CONTINUITY.md")

EXPECTED_SLICE_TITLES = {
    "E16-A1": "Historical Authority Continuity, Preservation Intent, Custodian and Replica Binding",
    "E16-A2": "Replica Placement, Custody Acceptance, Failure-Domain Declaration and Placement Evidence",
    "E16-A3": "Retention Windows, Bounded Preservation Observations, Independent Readback and Restore Verification",
    "E16-A4": "Custodian Succession, Replica Migration, Loss, Quarantine and Anti-Rollback Recovery",
    "E16-A5": "Independent Preservation Verifier Matrix, Differential Restore Replay and Final Freeze",
}
EXPECTED_REQUIRED_INPUTS = [
    "e15_final_closure_report",
    "e15_external_object_commitment",
    "custodian_profile",
    "replica_profile",
    "custody_policy",
    "placement_policy",
    "retention_policy",
    "restoration_policy",
    "observation_policy",
    "succession_policy",
    "evaluation_context",
    "idempotency_key",
]
EXPECTED_SAFETY_RULES = [
    "e15-publication-readback-does-not-imply-replication",
    "replica-registration-does-not-prove-physical-separation",
    "provider-distinct-label-does-not-prove-failure-domain-independence",
    "retention-policy-does-not-guarantee-future-retention",
    "repeated-readback-does-not-prove-indefinite-durability",
    "restore-success-at-one-time-does-not-prove-future-restorability",
    "current-multi-location-availability-does-not-prove-universal-availability",
    "custody-acceptance-does-not-transfer-legal-ownership",
    "deletion-at-one-custodian-does-not-prove-global-erasure",
    "known-negative-precedes-held-and-unavailable",
    "exact-source-binding-precedes-preservation-lifecycle-interpretation",
]
EXPECTED_NONCLAIMS = [
    "indefinite-durability",
    "universal-availability",
    "external-service-honesty",
    "provider-independence",
    "correlated-failure-resistance",
    "administrative-deletion-prevention",
    "legal-custody-or-ownership",
    "global-erasure",
    "globally-trusted-time",
    "collusion-resistance",
    "universal-interoperability",
]
EXPECTED_TRANSITION_VERIFY = [
    "exact-e15-source-commit",
    "all-e15-frozen-authority-digests-at-source-commit",
    "historical-e15-checker-and-matrix-replay-at-source-commit",
    "additive-e16-adoption",
    "no-rewrite-of-e15-claims",
    "new-central-profile-and-workflow-digests",
    "separate-e16-manual-gate",
]


def _load_json(path: Path, findings: list[dict[str, str]], code: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        findings.append({"code": f"{code}.MISSING", "path": path.as_posix(), "message": "required JSON authority is missing"})
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        findings.append({"code": f"{code}.INVALID", "path": path.as_posix(), "message": str(exc)})
    return None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_repository_path(value: str) -> bool:
    posix = PurePosixPath(value)
    return (
        bool(value)
        and not posix.is_absolute()
        and ".." not in posix.parts
        and "\\" not in value
        and value == posix.as_posix()
    )


def _expect(findings: list[dict[str, str]], condition: bool, code: str, path: str, message: str) -> None:
    if not condition:
        findings.append({"code": code, "path": path, "message": message})


def _check_authority(root: Path, findings: list[dict[str, str]]) -> dict[str, Any] | None:
    authority_path = root / AUTHORITY_PATH
    authority = _load_json(authority_path, findings, "M0A7.AUTHORITY")
    if not isinstance(authority, dict):
        return None

    _expect(findings, authority.get("standard") == STANDARD, "M0A7.STANDARD", AUTHORITY_PATH.as_posix(), "unexpected M0-A7 standard")
    _expect(
        findings,
        authority.get("status") == "ready-for-e16-a1-design-not-normatively-adopted",
        "M0A7.STATUS",
        AUTHORITY_PATH.as_posix(),
        "unexpected M0-A7 status",
    )

    source = authority.get("source_lineage")
    _expect(findings, isinstance(source, dict), "M0A7.SOURCE.TYPE", AUTHORITY_PATH.as_posix(), "source_lineage must be an object")
    if isinstance(source, dict):
        _expect(findings, source.get("branch") == SOURCE_BRANCH, "M0A7.SOURCE.BRANCH", AUTHORITY_PATH.as_posix(), "source branch changed")
        _expect(findings, source.get("head_commit") == SOURCE_HEAD, "M0A7.SOURCE.HEAD", AUTHORITY_PATH.as_posix(), "source head changed")
        _expect(findings, source.get("profile_revision") == SOURCE_PROFILE, "M0A7.SOURCE.PROFILE", AUTHORITY_PATH.as_posix(), "source profile changed")
        _expect(findings, source.get("authority") == FREEZE_PATH.as_posix(), "M0A7.SOURCE.FREEZE", AUTHORITY_PATH.as_posix(), "source freeze path changed")
        _expect(findings, source.get("final_closure") == FINAL_CLOSURE_PATH.as_posix(), "M0A7.SOURCE.CLOSURE", AUTHORITY_PATH.as_posix(), "source closure path changed")
        _expect(findings, source.get("required_terminal_slice") == "E15-A5", "M0A7.SOURCE.SLICE", AUTHORITY_PATH.as_posix(), "terminal slice changed")

    closure = authority.get("multiplatform_closure")
    _expect(findings, isinstance(closure, dict), "M0A7.CLOSURE.TYPE", AUTHORITY_PATH.as_posix(), "multiplatform_closure must be an object")
    if isinstance(closure, dict):
        _expect(findings, closure.get("e15_a4_historical_replay_run") == HISTORY_RUN, "M0A7.CLOSURE.HISTORY_RUN", AUTHORITY_PATH.as_posix(), "historical replay run changed")
        _expect(findings, closure.get("e15_a5_final_closure_run") == FINAL_RUN, "M0A7.CLOSURE.FINAL_RUN", AUTHORITY_PATH.as_posix(), "final closure run changed")
        _expect(findings, closure.get("platforms") == PLATFORMS, "M0A7.CLOSURE.PLATFORMS", AUTHORITY_PATH.as_posix(), "platform matrix changed")
        _expect(findings, closure.get("result") == "success", "M0A7.CLOSURE.RESULT", AUTHORITY_PATH.as_posix(), "closure result is not success")

    target = authority.get("target")
    _expect(findings, isinstance(target, dict), "M0A7.TARGET.TYPE", AUTHORITY_PATH.as_posix(), "target must be an object")
    if isinstance(target, dict):
        _expect(findings, target.get("identifier") == "E16", "M0A7.TARGET.ID", AUTHORITY_PATH.as_posix(), "target identifier changed")
        _expect(findings, target.get("working_title") == TARGET_TITLE, "M0A7.TARGET.TITLE", AUTHORITY_PATH.as_posix(), "target title changed")
        _expect(findings, target.get("first_principal_slice") == "E16-A1", "M0A7.TARGET.FIRST_SLICE", AUTHORITY_PATH.as_posix(), "first slice changed")
        _expect(findings, target.get("adoption_state") == "not-adopted", "M0A7.TARGET.ADOPTION", AUTHORITY_PATH.as_posix(), "E16 was prematurely adopted")
        _expect(findings, target.get("extension_file") is None, "M0A7.TARGET.EXTENSION", AUTHORITY_PATH.as_posix(), "E16 extension file must remain null")

    gate = authority.get("entry_gate")
    _expect(findings, isinstance(gate, dict), "M0A7.GATE.TYPE", AUTHORITY_PATH.as_posix(), "entry_gate must be an object")
    if isinstance(gate, dict):
        expected_gate = {
            "authority_continuity_bridge": "required-in-e16-a1",
            "central_profile_mutation": "forbidden-before-transition-bridge",
            "e15_final_closure": "complete",
            "e15_frozen_paths_unchanged": True,
            "e15_multiplatform_closure": "complete",
            "e16_normative_text": "not-created",
            "e16_schema_and_checker": "not-created",
            "readiness": "ready-for-e16-a1-design",
        }
        _expect(findings, gate == expected_gate, "M0A7.GATE.CONTENT", AUTHORITY_PATH.as_posix(), "entry gate differs from normalized contract")

    continuity = authority.get("authority_continuity")
    _expect(findings, isinstance(continuity, dict), "M0A7.CONTINUITY.TYPE", AUTHORITY_PATH.as_posix(), "authority_continuity must be an object")
    if isinstance(continuity, dict):
        _expect(findings, continuity.get("frozen_source_commit") == SOURCE_HEAD, "M0A7.CONTINUITY.HEAD", AUTHORITY_PATH.as_posix(), "continuity head changed")
        _expect(findings, continuity.get("current_tree_byte_equality_required_before_e16_a1") is True, "M0A7.CONTINUITY.BYTES", AUTHORITY_PATH.as_posix(), "current-tree byte equality is not required")
        _expect(findings, continuity.get("descendant_transition_required") is True, "M0A7.CONTINUITY.TRANSITION", AUTHORITY_PATH.as_posix(), "descendant transition is not required")
        _expect(findings, continuity.get("silent_retargeting_forbidden") is True, "M0A7.CONTINUITY.RETARGET", AUTHORITY_PATH.as_posix(), "silent retargeting is not forbidden")
        _expect(findings, continuity.get("transition_must_verify") == EXPECTED_TRANSITION_VERIFY, "M0A7.CONTINUITY.VERIFY", AUTHORITY_PATH.as_posix(), "transition verification set changed")

    _expect(findings, authority.get("required_inputs") == EXPECTED_REQUIRED_INPUTS, "M0A7.INPUTS", AUTHORITY_PATH.as_posix(), "required input list changed")
    _expect(findings, authority.get("safety_rules") == EXPECTED_SAFETY_RULES, "M0A7.SAFETY", AUTHORITY_PATH.as_posix(), "safety rules changed")
    _expect(findings, authority.get("nonclaims") == EXPECTED_NONCLAIMS, "M0A7.NONCLAIMS", AUTHORITY_PATH.as_posix(), "nonclaim list changed")

    vocabulary = authority.get("decision_vocabulary")
    _expect(findings, isinstance(vocabulary, dict), "M0A7.VOCABULARY.TYPE", AUTHORITY_PATH.as_posix(), "decision_vocabulary must be an object")
    if isinstance(vocabulary, dict):
        _expect(findings, vocabulary.get("gate") == ["permit", "deny", "held", "unavailable"], "M0A7.VOCABULARY.GATE", AUTHORITY_PATH.as_posix(), "gate vocabulary changed")
        _expect(findings, vocabulary.get("evidence") == ["absent", "pending", "positive", "negative", "contested", "unavailable"], "M0A7.VOCABULARY.EVIDENCE", AUTHORITY_PATH.as_posix(), "evidence vocabulary changed")

    slices = authority.get("planned_slices")
    _expect(findings, isinstance(slices, list), "M0A7.SLICES.TYPE", AUTHORITY_PATH.as_posix(), "planned_slices must be an array")
    if isinstance(slices, list):
        ids = [item.get("id") for item in slices if isinstance(item, dict)]
        _expect(findings, ids == list(EXPECTED_SLICE_TITLES), "M0A7.SLICES.ORDER", AUTHORITY_PATH.as_posix(), "slice sequence changed")
        for item in slices:
            if not isinstance(item, dict):
                continue
            slice_id = item.get("id")
            if slice_id in EXPECTED_SLICE_TITLES:
                _expect(findings, item.get("title") == EXPECTED_SLICE_TITLES[slice_id], "M0A7.SLICES.TITLE", AUTHORITY_PATH.as_posix(), f"title changed for {slice_id}")
                _expect(findings, item.get("status") == "planned-not-created", "M0A7.SLICES.STATUS", AUTHORITY_PATH.as_posix(), f"{slice_id} is prematurely created")

    methodology = authority.get("methodology_translation")
    _expect(findings, isinstance(methodology, dict), "M0A7.METHODOLOGY.TYPE", AUTHORITY_PATH.as_posix(), "methodology_translation must be an object")
    if isinstance(methodology, dict):
        _expect(findings, methodology.get("mode") == "typed-derived-rules-only", "M0A7.METHODOLOGY.MODE", AUTHORITY_PATH.as_posix(), "methodology mode changed")
        _expect(findings, methodology.get("direct_source_republication") is False, "M0A7.METHODOLOGY.REPUBLICATION", AUTHORITY_PATH.as_posix(), "direct source republication enabled")
        _expect(findings, methodology.get("source_equations_allowed") is False, "M0A7.METHODOLOGY.EQUATIONS", AUTHORITY_PATH.as_posix(), "source equations enabled")
        _expect(findings, methodology.get("source_specific_terminology_allowed") is False, "M0A7.METHODOLOGY.TERMS", AUTHORITY_PATH.as_posix(), "source-specific terminology enabled")
        rules = methodology.get("rules")
        _expect(findings, isinstance(rules, list) and len(rules) == 7, "M0A7.METHODOLOGY.RULES", AUTHORITY_PATH.as_posix(), "methodology rule count changed")

    return authority


def _check_frozen_authorities(root: Path, findings: list[dict[str, str]]) -> int:
    freeze = _load_json(root / FREEZE_PATH, findings, "M0A7.FREEZE")
    if not isinstance(freeze, dict):
        return 0
    _expect(findings, freeze.get("standard") == "EIGIIB-E15-A5-FREEZE-1.0", "M0A7.FREEZE.STANDARD", FREEZE_PATH.as_posix(), "unexpected E15 freeze standard")
    _expect(findings, freeze.get("status") == "frozen", "M0A7.FREEZE.STATUS", FREEZE_PATH.as_posix(), "E15 freeze is not frozen")
    _expect(findings, freeze.get("profile_revision") == SOURCE_PROFILE, "M0A7.FREEZE.PROFILE", FREEZE_PATH.as_posix(), "E15 freeze profile changed")
    authorities = freeze.get("authorities")
    if not isinstance(authorities, list):
        findings.append({"code": "M0A7.FREEZE.AUTHORITIES", "path": FREEZE_PATH.as_posix(), "message": "authorities must be an array"})
        return 0
    _expect(findings, len(authorities) == 86, "M0A7.FREEZE.COUNT", FREEZE_PATH.as_posix(), "E15 freeze must contain exactly 86 authorities")
    seen: set[str] = set()
    for entry in authorities:
        if not isinstance(entry, dict):
            findings.append({"code": "M0A7.FREEZE.ENTRY", "path": FREEZE_PATH.as_posix(), "message": "freeze entry must be an object"})
            continue
        path_value = entry.get("path")
        if not isinstance(path_value, str) or not _safe_repository_path(path_value):
            findings.append({"code": "M0A7.FREEZE.PATH", "path": FREEZE_PATH.as_posix(), "message": f"unsafe authority path: {path_value!r}"})
            continue
        if path_value in seen:
            findings.append({"code": "M0A7.FREEZE.DUPLICATE", "path": path_value, "message": "duplicate authority path"})
            continue
        seen.add(path_value)
        path = root / path_value
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append({"code": "M0A7.FREEZE.MISSING", "path": path_value, "message": str(exc)})
            continue
        _expect(findings, entry.get("bytes") == len(data), "M0A7.FREEZE.BYTES", path_value, "authority byte count changed")
        _expect(findings, entry.get("sha256") == _digest(data), "M0A7.FREEZE.DIGEST", path_value, "authority digest changed")
    return len(authorities)


def _check_profile_and_absence(root: Path, findings: list[dict[str, str]]) -> None:
    profile_path = root / "EIGIIB.toml"
    try:
        profile = tomllib.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        findings.append({"code": "M0A7.PROFILE.INVALID", "path": "EIGIIB.toml", "message": str(exc)})
        return
    extensions = profile.get("extensions", [])
    authorities = profile.get("authorities", {})
    _expect(findings, profile.get("revision") == SOURCE_PROFILE, "M0A7.PROFILE.REVISION", "EIGIIB.toml", "central profile revision changed")
    _expect(findings, "E15-1.0" in extensions, "M0A7.PROFILE.E15", "EIGIIB.toml", "E15 is no longer adopted")
    _expect(findings, "E16-1.0" not in extensions, "M0A7.E16.PREMATURE", "EIGIIB.toml", "E16 was prematurely adopted")
    _expect(findings, isinstance(authorities, dict) and "e16" not in authorities, "M0A7.E16.AUTHORITY", "EIGIIB.toml", "E16 authority was prematurely registered")

    graph = _load_json(root / "conformance/extension-graph.json", findings, "M0A7.GRAPH")
    if isinstance(graph, dict):
        nodes = graph.get("nodes", [])
        ids = {item.get("id") for item in nodes if isinstance(item, dict)}
        _expect(findings, "E15" in ids, "M0A7.GRAPH.E15", "conformance/extension-graph.json", "E15 graph node missing")
        _expect(findings, "E16" not in ids, "M0A7.E16.GRAPH", "conformance/extension-graph.json", "E16 graph node was prematurely created")

    forbidden_patterns = [
        "extensions/E16-*.md",
        "schemas/eigiib-e16-*.schema.json",
        "tools/eigiib_e16_*.py",
        "conformance/e16-*.json",
        "tests/test_eigiib_e16*.py",
    ]
    forbidden = sorted(
        path.relative_to(root).as_posix()
        for pattern in forbidden_patterns
        for path in root.glob(pattern)
        if path.is_file()
    )
    _expect(findings, not forbidden, "M0A7.E16.ARTIFACT", ".", f"premature E16 artifacts: {forbidden}")


def _check_required_documents(root: Path, findings: list[dict[str, str]]) -> None:
    for path in (MANUAL_PATH, GUIDE_PATH, CONTRACT_PATH):
        _expect(findings, (root / path).is_file(), "M0A7.DOCUMENT.MISSING", path.as_posix(), "required M0-A7 document missing")


def evaluate(root: Path) -> dict[str, Any]:
    root = root.resolve()
    findings: list[dict[str, str]] = []
    authority = _check_authority(root, findings)
    authority_ok = not findings and authority is not None
    before_freeze = len(findings)
    authority_count = _check_frozen_authorities(root, findings)
    freeze_ok = len(findings) == before_freeze
    before_profile = len(findings)
    _check_profile_and_absence(root, findings)
    _check_required_documents(root, findings)
    profile_and_documents_ok = len(findings) == before_profile
    normalization_ok = authority_ok and profile_and_documents_ok
    continuity_ok = authority_ok and freeze_ok
    closure = authority.get("multiplatform_closure") if isinstance(authority, dict) else None
    closure_ok = isinstance(closure, dict) and closure.get("result") == "success" and closure.get("platforms") == PLATFORMS
    slices = authority.get("planned_slices") if isinstance(authority, dict) else None

    return {
        "authority_count": authority_count,
        "authority_freeze_result": "conformant" if freeze_ok else "non-conformant",
        "entry_normalization_result": "conformant" if normalization_ok else "non-conformant",
        "findings": findings,
        "historical_continuity_result": "conformant" if continuity_ok else "non-conformant",
        "multiplatform_closure_result": "conformant" if closure_ok else "non-conformant",
        "planned_slice_count": len(slices) if isinstance(slices, list) else 0,
        "standard": STANDARD,
        "structural_result": "conformant" if not findings else "non-conformant",
        "target": "E16",
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--output", help="write the report to this path")
    args = parser.parse_args(argv)

    report = evaluate(Path(args.root))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8", newline="\n")
    if args.json or not args.output:
        sys.stdout.write(rendered)
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
