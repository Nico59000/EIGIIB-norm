#!/usr/bin/env python3
"""Validate the M0-A5 canonical P1 lineage and E14 design handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib

EXPECTED_IDS = [
    "P1-A1", "P1-A2", "P1-A3", "P1-A4", "P1-A5", "P1-A6", "P1-A7",
    "P1-A8", "P1-A9", "P1-A10", "P1-A11", "P1-A12", "P1-A13",
    "P1-A14", "P1-A15", "P1-A16", "P1-A17", "P1-A18", "P1-A19",
    "P1-A19-F2", "P1-A20",
]
EXPECTED_HEADS = {
    "P1-A1": "7c0e8c24562a96eab7323c66cf53a8c3da8ec171",
    "P1-A2": "7062f67d31037401e892eb0237a775d3a4b18ca0",
    "P1-A3": "c9ee247fe38f8b4e90d083f3bea4c92d50ad664d",
    "P1-A4": "3592b245f871cff8ced88657012abf807b4c3d03",
    "P1-A5": "6cfb1ab89aa5065b87059171720b3f83230afc2d",
    "P1-A6": "784fdf48bdc9a5c733735da049a8c87022c87b1b",
    "P1-A7": "a478bda55bb88bb3fa611e3ae52a9ce880d2243b",
    "P1-A8": "7a7a4ece20a5f03029e24c5ab7e7685cab15d7c3",
    "P1-A9": "d854ab836a9cdf23f88f23d620e1d61fd6bfcdf6",
    "P1-A10": "d2fcb409c93f88e41c1ce084aa29baffc1809581",
    "P1-A11": "356949456e8d4084ce317f45f5912522150ecd97",
    "P1-A12": "286c17db08911ae22202aa30c90cac10dc3c61b8",
    "P1-A13": "077634971f2c16f3f74eb4c6c5b75aa7099bee55",
    "P1-A14": "586784811f1139349141728c6db966f7f54459a1",
    "P1-A15": "461412075d97d9b8a8202e89fc3a9da3b6743f1b",
    "P1-A16": "020cbfc29aaeccb51606021669b7f381f2ec00f6",
    "P1-A17": "2e2ea29ac61787cb62c22f7db828766257af4c01",
    "P1-A18": "be2eda2c9a86c703c6d486599d1062143c228ca9",
    "P1-A19": "d791f780bc97d70e8f97e5165d3c86dc4a90fddf",
    "P1-A19-F2": "66b25d4f27ded3e273922f9fdcf80b9c88c8c808",
    "P1-A20": "c1983e9f2e95879ee16c162075c8d72bc73d88f9",
}
EXPECTED_BRANCH = "agent/p1-a20-registered-runner-admission-toolchain-succession-compatibility-rollback"
EXPECTED_INPUTS = [
    "authorized_audience",
    "correlation_controls",
    "cryptographic_commitment",
    "disclosable_projection",
    "disclosure_policy",
    "evaluation_context",
    "full_evidence_artifact",
    "revocation_state",
]
EXPECTED_DECISIONS = ["permit", "deny", "held", "unavailable"]
EXPECTED_NONCLAIMS = [
    "anonymity",
    "confidential-storage",
    "long-term-cryptographic-validity",
    "post-quantum-resistance",
    "unlinkability",
    "zero-knowledge",
]
EXPECTED_REPORT_PATH = "tests/fixtures/m0-a5/expected-report.json"
EXPECTED_REPORT_SHA256 = "f7829589228cf480c3b69f4e954edf882eea238301aefdd16e34a00422abace6"
EXPECTED_REPORT_BYTE_LENGTH = 587
EXPECTED_FREEZE_PATH = "conformance/m0-a5-f1-authority-freeze.json"

EXPECTED_SAFETY_RULES = [
    "a-permitted-source-claim-does-not-imply-disclosure-is-permitted",
    "missing-required-input-cannot-be-promoted-to-permit",
    "context-or-policy-change-requires-new-evaluation",
    "projection-must-not-strengthen-source-claim",
    "revoked-or-withdrawn-authority-cannot-be-silently-reused",
    "every-crossing-must-preserve-source-identity-and-claim-boundary",
]


class ValidationError(ValueError):
    pass


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{path}: top level must be an object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def confined_file(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and relative and not relative.startswith("/"), f"invalid path: {relative!r}")
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    require(candidate == root_resolved or root_resolved in candidate.parents, f"path escapes repository: {relative}")
    require(candidate.is_file(), f"missing referenced authority: {relative}")
    return candidate


def validate_lineage(root: Path, registry: dict) -> set[str]:
    require(registry.get("standard") == "EIGIIB-M0-A5-P1-LINEAGE-1.0", "unexpected lineage standard")
    require(registry.get("status") == "canonical-p1-lineage-promoted", "lineage is not promoted")

    canonical = registry.get("canonical")
    require(isinstance(canonical, dict), "canonical must be an object")
    require(canonical.get("branch") == EXPECTED_BRANCH, "canonical branch mismatch")
    require(canonical.get("head_commit") == EXPECTED_HEADS["P1-A20"], "canonical head mismatch")
    require(canonical.get("head_slice") == "P1-A20", "canonical head slice mismatch")
    require(canonical.get("promotion_rule") == "exact-commit-and-path-reference-only", "unsafe promotion rule")

    slices = registry.get("slices")
    require(isinstance(slices, list), "slices must be an array")
    ids = [entry.get("id") for entry in slices if isinstance(entry, dict)]
    require(ids == EXPECTED_IDS, "slice order or membership mismatch")

    referenced: set[str] = set()
    previous_head: str | None = None
    for entry in slices:
        require(isinstance(entry, dict), "slice entry must be an object")
        slice_id = entry["id"]
        require(entry.get("head_commit") == EXPECTED_HEADS[slice_id], f"{slice_id}: head mismatch")
        if previous_head is not None:
            require(entry.get("base_commit") == previous_head, f"{slice_id}: base mismatch")
        else:
            require(entry.get("base_commit") is None, "P1-A1 must be the P1 root entry")
        expected_span = "35-commit-staged-closure" if slice_id == "P1-A7" else ("p1-root" if slice_id == "P1-A1" else "single-child")
        require(entry.get("commit_span") == expected_span, f"{slice_id}: commit span mismatch")
        require(entry.get("promotion_status") == "promoted-by-m0-a5-index", f"{slice_id}: not promoted")
        require(entry.get("authority_mode") == "reference-not-copy", f"{slice_id}: authority content duplicated")
        for key in ("document", "state", "manual_review"):
            path = entry.get(key)
            confined_file(root, path)
            referenced.add(path)
        previous_head = entry["head_commit"]

    closures = registry.get("embedded_staged_closures")
    require(isinstance(closures, dict) and set(closures) == {"P1-A7"}, "unexpected staged closures")
    stages = closures["P1-A7"]
    require(isinstance(stages, list) and [s.get("id") for s in stages] == [f"P1-A7.{n}" for n in range(1, 8)], "A7 stage order mismatch")
    for stage in stages:
        for key in ("document", "manual_review"):
            path = stage.get(key)
            confined_file(root, path)
            referenced.add(path)
    require(stages[5].get("commit") == "5e652647ab40d55c1041a2b4a4432931a62e95e8", "A7.6 source mismatch")
    require(stages[6].get("commit") == EXPECTED_HEADS["P1-A7"], "A7.7 head mismatch")
    require(all(stage.get("commit_binding") == "transitively-frozen-by-p1-a7.7" for stage in stages[:5]), "A7.1-A7.5 binding mismatch")

    governance = registry.get("governance")
    require(isinstance(governance, dict), "governance must be an object")
    require(governance.get("pr_state_is_authority") is False, "PR state cannot be authority")
    require(governance.get("branch_name_is_sufficient_authority") is False, "branch name cannot be sufficient authority")
    require(governance.get("exact_commit_is_required") is True, "exact commit requirement missing")
    require(governance.get("silent_retargeting_forbidden") is True, "silent retargeting must be forbidden")
    return referenced


def validate_handoff(root: Path, handoff: dict) -> None:
    require(handoff.get("standard") == "EIGIIB-M0-A5-E14-HANDOFF-1.0", "unexpected handoff standard")
    require(handoff.get("status") == "ready-for-e14-design-not-normatively-adopted", "unsafe E14 handoff status")
    source = handoff.get("source_lineage")
    require(isinstance(source, dict), "source_lineage must be an object")
    require(source.get("authority") == "conformance/m0-a5-p1-lineage.json", "handoff lineage authority mismatch")
    require(source.get("canonical_head_commit") == EXPECTED_HEADS["P1-A20"], "handoff source head mismatch")
    require(source.get("required_terminal_slice") == "P1-A20", "handoff terminal slice mismatch")

    target = handoff.get("target")
    require(isinstance(target, dict), "target must be an object")
    require(target.get("identifier") == "E14", "target identifier mismatch")
    require(target.get("extension_file") is None, "M0-A5 must not create an E14 extension file")
    require(target.get("adoption_state") == "not-adopted", "E14 must remain unadopted")

    require(handoff.get("required_inputs") == EXPECTED_INPUTS, "E14 input set or order mismatch")
    contract = handoff.get("input_contract")
    require(isinstance(contract, dict) and sorted(contract) == EXPECTED_INPUTS, "E14 input contract mismatch")
    require(handoff.get("decision_vocabulary") == EXPECTED_DECISIONS, "decision vocabulary mismatch")
    require(handoff.get("safety_rules") == EXPECTED_SAFETY_RULES, "safety rule mismatch")
    require(handoff.get("nonclaims") == EXPECTED_NONCLAIMS, "nonclaim mismatch")

    gate = handoff.get("entry_gate")
    require(isinstance(gate, dict), "entry_gate must be an object")
    require(gate.get("lineage_inventory") == "complete", "lineage inventory gate incomplete")
    require(gate.get("authority_promotion") == "complete", "authority promotion gate incomplete")
    require(gate.get("human_control_documentation") == "complete", "human documentation gate incomplete")
    require(gate.get("e14_normative_text") == "not-created", "E14 normative text was created too early")
    require(gate.get("e14_schema_and_checker") == "not-created", "E14 implementation was created too early")
    require(gate.get("readiness") == "ready-for-design", "E14 design readiness mismatch")


def canonical_report_bytes(report: dict) -> bytes:
    """Serialize a report to the repository's byte-exact JSON form."""
    return (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_canonical_report(path: Path, report: dict) -> None:
    """Write canonical bytes without platform newline translation."""
    path.write_bytes(canonical_report_bytes(report))


def validate_freeze(root: Path, report: dict) -> None:
    freeze = load_json(root / EXPECTED_FREEZE_PATH)
    require(freeze.get("standard") == "EIGIIB-M0-A5-F1-AUTHORITY-FREEZE-1.0", "unexpected M0-A5-F1 freeze standard")
    require(freeze.get("status") == "frozen", "M0-A5-F1 authority is not frozen")

    source = freeze.get("source")
    require(isinstance(source, dict), "M0-A5-F1 source must be an object")
    require(source.get("branch") == "agent/m0-a5-canonical-p1-lineage-authority-promotion-e14-handoff", "M0-A5-F1 branch mismatch")
    require(source.get("pre_fix_head_commit") == "85df644e67a610a8645b753177f0f2056d0452b3", "M0-A5-F1 pre-fix head mismatch")
    require(source.get("canonical_p1_head_commit") == EXPECTED_HEADS["P1-A20"], "M0-A5-F1 canonical P1 head mismatch")

    canonical = freeze.get("canonical_report")
    require(isinstance(canonical, dict), "M0-A5-F1 canonical_report must be an object")
    require(canonical.get("path") == EXPECTED_REPORT_PATH, "M0-A5-F1 report path mismatch")
    require(canonical.get("encoding") == "utf-8", "M0-A5-F1 report encoding mismatch")
    require(canonical.get("newline") == "lf", "M0-A5-F1 report newline mismatch")
    require(canonical.get("terminal_newline_count") == 1, "M0-A5-F1 terminal newline mismatch")
    require(canonical.get("byte_length") == EXPECTED_REPORT_BYTE_LENGTH, "M0-A5-F1 byte length mismatch")
    require(canonical.get("sha256") == EXPECTED_REPORT_SHA256, "M0-A5-F1 report digest mismatch")

    expected_path = confined_file(root, EXPECTED_REPORT_PATH)
    expected_bytes = expected_path.read_bytes()
    require(len(expected_bytes) == EXPECTED_REPORT_BYTE_LENGTH, "canonical report fixture byte length changed")
    require(hashlib.sha256(expected_bytes).hexdigest() == EXPECTED_REPORT_SHA256, "canonical report fixture digest changed")
    require(expected_bytes.endswith(b"\n") and not expected_bytes.endswith(b"\r\n"), "canonical report fixture must end in one LF")
    require(expected_bytes.count(b"\r") == 0, "canonical report fixture contains carriage returns")
    require(canonical_report_bytes(report) == expected_bytes, "canonical report bytes differ from frozen fixture")

    writer = freeze.get("writer_contract")
    require(isinstance(writer, dict), "M0-A5-F1 writer_contract must be an object")
    require(writer.get("serialization") == "json-sort-keys-compact", "M0-A5-F1 serialization mismatch")
    require(writer.get("output_mode") == "binary-exact", "M0-A5-F1 output mode mismatch")
    require(writer.get("text_newline_translation") == "forbidden", "M0-A5-F1 newline translation must be forbidden")
    require(writer.get("write_api") == "Path.write_bytes", "M0-A5-F1 writer API mismatch")
    require(writer.get("platforms") == ["ubuntu-24.04", "macos-15", "windows-2025"], "M0-A5-F1 platform matrix mismatch")

    authority = freeze.get("authority_freeze")
    require(isinstance(authority, dict), "M0-A5-F1 authority_freeze must be an object")
    require(authority.get("lineage") == "conformance/m0-a5-p1-lineage.json", "M0-A5-F1 lineage authority mismatch")
    require(authority.get("e14_handoff") == "conformance/m0-a5-e14-handoff.json", "M0-A5-F1 E14 handoff mismatch")
    require(authority.get("human_mastery") == "docs/M0-A5-HUMAN-MASTERY-GUIDE.md", "M0-A5-F1 human guide mismatch")
    require(authority.get("closure_document") == "docs/M0-A5-F1-CROSS-PLATFORM-CANONICAL-REPORT-NORMALIZATION-WINDOWS-BYTE-EXACT-REPLAY-AND-FINAL-AUTHORITY-FREEZE.md", "M0-A5-F1 closure document mismatch")
    require(authority.get("manual_review") == "conformance/M0-A5-F1-MANUAL-REVIEW.md", "M0-A5-F1 manual review mismatch")
    require(authority.get("e14_adopted") is False, "M0-A5-F1 must not adopt E14")
    require(authority.get("silent_retargeting_forbidden") is True, "M0-A5-F1 silent retargeting must remain forbidden")
    for key in ("lineage", "e14_handoff", "human_mastery", "closure_document", "manual_review"):
        confined_file(root, authority[key])


def validate_adoption_profile(root: Path) -> None:
    profile_path = root / "EIGIIB.toml"
    try:
        profile = tomllib.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"{profile_path}: {exc}") from exc

    extensions = profile.get("extensions")
    require(isinstance(extensions, list) and "E14-1.0" not in extensions and "E14" not in extensions, "E14 is prematurely adopted")

    required = profile.get("required_authorities")
    require(isinstance(required, list), "required_authorities must be an array")
    for authority in ("m0_a5_p1_lineage", "m0_a5_e14_handoff", "m0_a5_human_mastery", "m0_a5_f1_authority_freeze"):
        require(authority in required, f"missing required authority: {authority}")

    authorities = profile.get("authorities")
    require(isinstance(authorities, dict), "authorities must be a table")
    expected = {
        "m0_a5_p1_lineage": "conformance/m0-a5-p1-lineage.json",
        "m0_a5_e14_handoff": "conformance/m0-a5-e14-handoff.json",
        "m0_a5_human_mastery": "docs/M0-A5-HUMAN-MASTERY-GUIDE.md",
        "m0_a5_f1_authority_freeze": EXPECTED_FREEZE_PATH,
    }
    for key, path in expected.items():
        require(authorities.get(key) == path, f"authority path mismatch: {key}")
        confined_file(root, path)

    gates = profile.get("manual_gates")
    require(isinstance(gates, list), "manual_gates must be an array")
    matches = [g for g in gates if isinstance(g, dict) and g.get("id") == "m0-a5-lineage-e14-handoff-review"]
    require(len(matches) == 1, "M0-A5 manual gate missing or duplicated")
    gate = matches[0]
    require(gate.get("status") == "complete", "M0-A5 manual gate incomplete")
    require(gate.get("authority") == "m0_a5_p1_lineage", "M0-A5 manual gate authority mismatch")
    require(gate.get("attestation") == "conformance/M0-A5-MANUAL-REVIEW.md", "M0-A5 attestation mismatch")
    confined_file(root, gate["attestation"])

    freeze_matches = [g for g in gates if isinstance(g, dict) and g.get("id") == "m0-a5-f1-cross-platform-authority-freeze-review"]
    require(len(freeze_matches) == 1, "M0-A5-F1 manual gate missing or duplicated")
    freeze_gate = freeze_matches[0]
    require(freeze_gate.get("status") == "complete", "M0-A5-F1 manual gate incomplete")
    require(freeze_gate.get("authority") == "m0_a5_f1_authority_freeze", "M0-A5-F1 manual gate authority mismatch")
    require(freeze_gate.get("attestation") == "conformance/M0-A5-F1-MANUAL-REVIEW.md", "M0-A5-F1 attestation mismatch")
    confined_file(root, freeze_gate["attestation"])


def validate(root: Path) -> dict:
    lineage = load_json(root / "conformance/m0-a5-p1-lineage.json")
    handoff = load_json(root / "conformance/m0-a5-e14-handoff.json")
    referenced = validate_lineage(root, lineage)
    validate_handoff(root, handoff)
    validate_adoption_profile(root)

    report = {
        "standard": "EIGIIB-M0-A5-CHECK-1.0",
        "overallResult": "conformant",
        "boundary": "canonical-p1-lineage-reference-only-authority-promotion-and-e14-design-handoff",
        "canonicalBranch": EXPECTED_BRANCH,
        "canonicalHeadCommit": EXPECTED_HEADS["P1-A20"],
        "promotedSliceCount": len(EXPECTED_IDS),
        "embeddedA7StageCount": 7,
        "uniqueReferencedSliceAuthorityFileCount": len(referenced),
        "e14RequiredInputCount": len(EXPECTED_INPUTS),
        "e14DecisionVocabulary": EXPECTED_DECISIONS,
        "e14Adopted": False,
        "humanMasteryGuide": "docs/M0-A5-HUMAN-MASTERY-GUIDE.md",
    }
    validate_freeze(root, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        report = validate(Path(args.root))
    except ValidationError as exc:
        print(f"M0-A5 validation failed: {exc}", file=sys.stderr)
        return 1
    encoded = canonical_report_bytes(report)
    if args.output:
        write_canonical_report(Path(args.output), report)
    else:
        sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
