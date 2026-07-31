#!/usr/bin/env python3
"""Build and verify EIGIIB P1-A1 in-toto Statement capsules.

P1-A1 intentionally stops at the Statement layer. It does not create or
verify a DSSE/Sigstore envelope, signature, certificate, timestamp, or
transparency receipt.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-P1-A1-1.0"
SOURCE_STANDARD = "EIGIIB-M0-A2-1.0"
PROFILE_ID = "in-toto-aggregate-export-v1"
EXTERNAL_SPEC_ID = "in-toto-attestation-1.2.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://eigiib.example/attestation/aggregate-conformance/v1"
ALLOWED_RESULTS = {
    "conformant",
    "conformant-with-documented-deviations",
    "incomplete",
    "non-conformant",
}
BOUNDARIES = [
    "statement-format-validity-does-not-imply-eigiib-claim-truth",
    "statement-presence-does-not-imply-e4-authentication",
    "subject-digest-match-does-not-imply-source-authenticity",
    "transported-aggregate-result-does-not-imply-production-conformance",
    "p1-a1-capsule-does-not-imply-envelope-or-signature",
]
TOP_FIELDS = {
    "standard", "profile", "external_spec", "transport_layer",
    "authentication_state", "statement",
}
STATEMENT_FIELDS = {"_type", "subject", "predicateType", "predicate"}
PREDICATE_FIELDS = {
    "eigiibProfile", "sourceStandard", "aggregateReport",
    "aggregateResult", "claimBoundary",
}
REPORT_FIELDS = {"mediaType", "contentEncoding", "data", "identity"}
RESULT_FIELDS = {"carrier", "value"}
BOUNDARY_FIELDS = {"authority", "transportOnly", "doesNotImply"}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def _identity(raw: bytes) -> dict[str, Any]:
    return {"algorithm": "sha256", "digest": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _load_report_bytes(raw: bytes) -> tuple[dict[str, Any] | None, list[Finding]]:
    findings: list[Finding] = []
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return None, [Finding("error", "P1A1.SOURCE.PARSE", "source", str(exc))]
    if not isinstance(obj, dict):
        return None, [Finding("error", "P1A1.SOURCE.TYPE", "source", "aggregate report root must be an object")]
    if obj.get("standard") != SOURCE_STANDARD:
        findings.append(Finding("error", "P1A1.SOURCE.STANDARD", "source.standard", f"standard must be {SOURCE_STANDARD}"))
    result = obj.get("overall_result")
    if result not in ALLOWED_RESULTS:
        findings.append(Finding("error", "P1A1.SOURCE.RESULT", "source.overall_result", "unsupported aggregate overall_result"))
    return obj, findings


def build_capsule(raw: bytes, subject_name: str) -> dict[str, Any]:
    report, findings = _load_report_bytes(raw)
    if findings:
        raise ValueError("; ".join(f"{f.code}: {f.message}" for f in findings))
    if not isinstance(subject_name, str) or not subject_name:
        raise ValueError("subject name must be non-empty")
    ident = _identity(raw)
    encoded = base64.b64encode(raw).decode("ascii")
    assert report is not None
    return {
        "standard": STANDARD,
        "profile": PROFILE_ID,
        "external_spec": EXTERNAL_SPEC_ID,
        "transport_layer": "in-toto-statement-v1",
        "authentication_state": "not-provided-p1-a1",
        "statement": {
            "_type": STATEMENT_TYPE,
            "subject": [{"name": subject_name, "digest": {"sha256": ident["digest"]}}],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "eigiibProfile": PROFILE_ID,
                "sourceStandard": SOURCE_STANDARD,
                "aggregateReport": {
                    "mediaType": "application/json",
                    "contentEncoding": "base64",
                    "data": encoded,
                    "identity": ident,
                },
                "aggregateResult": {
                    "carrier": "overall_result",
                    "value": report["overall_result"],
                },
                "claimBoundary": {
                    "authority": "aggregate_conformance",
                    "transportOnly": True,
                    "doesNotImply": BOUNDARIES[:],
                },
            },
        },
    }


def validate_capsule(obj: Any, source_raw: bytes | None = None) -> dict[str, Any]:
    findings: list[Finding] = []

    def add(code: str, path: str, message: str) -> None:
        findings.append(Finding("error", code, path, message))

    if not isinstance(obj, dict):
        add("P1A1.CAPSULE.TYPE", "", "capsule root must be an object")
        return result(findings)

    unknown = set(obj) - TOP_FIELDS
    if unknown:
        add("P1A1.CAPSULE.FIELD", "", "unexpected top-level fields: " + ", ".join(sorted(unknown)))
    for key in TOP_FIELDS:
        if key not in obj:
            add("P1A1.CAPSULE.REQUIRED", key, f"missing field {key}")

    expected_scalars = {
        "standard": STANDARD,
        "profile": PROFILE_ID,
        "external_spec": EXTERNAL_SPEC_ID,
        "transport_layer": "in-toto-statement-v1",
        "authentication_state": "not-provided-p1-a1",
    }
    for key, expected in expected_scalars.items():
        if obj.get(key) != expected:
            add("P1A1.CAPSULE.CONST", key, f"{key} must be {expected}")

    st = obj.get("statement")
    if not isinstance(st, dict):
        add("P1A1.STATEMENT.TYPE", "statement", "statement must be an object")
        return result(findings)
    if set(st) != STATEMENT_FIELDS:
        add("P1A1.STATEMENT.FIELD", "statement", "statement must contain exactly _type, subject, predicateType, predicate")
    if st.get("_type") != STATEMENT_TYPE:
        add("P1A1.STATEMENT.TYPE_URI", "statement._type", "unexpected in-toto Statement type")
    if st.get("predicateType") != PREDICATE_TYPE:
        add("P1A1.STATEMENT.PREDICATE_TYPE", "statement.predicateType", "unexpected EIGIIB predicate type")

    subjects = st.get("subject")
    subject_digest = None
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        add("P1A1.STATEMENT.SUBJECT", "statement.subject", "P1-A1 requires exactly one subject descriptor")
    else:
        subject = subjects[0]
        if set(subject) != {"name", "digest"} or not isinstance(subject.get("name"), str) or not subject.get("name"):
            add("P1A1.STATEMENT.SUBJECT", "statement.subject[0]", "subject must contain non-empty name and digest only")
        digest = subject.get("digest")
        if not isinstance(digest, dict) or set(digest) != {"sha256"}:
            add("P1A1.STATEMENT.DIGEST", "statement.subject[0].digest", "subject digest must contain only sha256")
        else:
            subject_digest = digest.get("sha256")
            if not isinstance(subject_digest, str) or not re_hex64(subject_digest):
                add("P1A1.STATEMENT.DIGEST", "statement.subject[0].digest.sha256", "sha256 must be 64 lowercase hex")

    pred = st.get("predicate")
    if not isinstance(pred, dict):
        add("P1A1.PREDICATE.TYPE", "statement.predicate", "predicate must be an object")
        return result(findings)
    if set(pred) != PREDICATE_FIELDS:
        add("P1A1.PREDICATE.FIELD", "statement.predicate", "predicate fields do not match P1-A1")
    if pred.get("eigiibProfile") != PROFILE_ID:
        add("P1A1.PREDICATE.PROFILE", "statement.predicate.eigiibProfile", "profile id mismatch")
    if pred.get("sourceStandard") != SOURCE_STANDARD:
        add("P1A1.PREDICATE.SOURCE_STANDARD", "statement.predicate.sourceStandard", "source standard mismatch")

    ar = pred.get("aggregateReport")
    decoded = None
    identity = None
    if not isinstance(ar, dict) or set(ar) != REPORT_FIELDS:
        add("P1A1.REPORT.FIELD", "statement.predicate.aggregateReport", "aggregateReport fields do not match P1-A1")
    else:
        if ar.get("mediaType") != "application/json" or ar.get("contentEncoding") != "base64":
            add("P1A1.REPORT.MEDIA", "statement.predicate.aggregateReport", "aggregate report must be base64 application/json")
        data = ar.get("data")
        if not isinstance(data, str):
            add("P1A1.REPORT.DATA", "statement.predicate.aggregateReport.data", "data must be base64 string")
        else:
            try:
                decoded = base64.b64decode(data, validate=True)
            except (binascii.Error, ValueError):
                add("P1A1.REPORT.BASE64", "statement.predicate.aggregateReport.data", "data is not strict base64")
        identity = ar.get("identity")
        if not valid_identity(identity):
            add("P1A1.REPORT.IDENTITY", "statement.predicate.aggregateReport.identity", "invalid source identity")

    report = None
    if decoded is not None:
        report, source_findings = _load_report_bytes(decoded)
        findings.extend(source_findings)
        actual = _identity(decoded)
        if valid_identity(identity) and identity != actual:
            add("P1A1.REPORT.IDENTITY_MISMATCH", "statement.predicate.aggregateReport.identity", "identity does not match transported bytes")
        if isinstance(subject_digest, str) and subject_digest != actual["digest"]:
            add("P1A1.STATEMENT.SUBJECT_MISMATCH", "statement.subject[0].digest.sha256", "subject digest does not match transported report")
        if source_raw is not None and source_raw != decoded:
            add("P1A1.SOURCE.MISMATCH", "statement.predicate.aggregateReport.data", "transported bytes differ from supplied source")

    agg_result = pred.get("aggregateResult")
    if not isinstance(agg_result, dict) or set(agg_result) != RESULT_FIELDS:
        add("P1A1.RESULT.FIELD", "statement.predicate.aggregateResult", "aggregateResult fields do not match P1-A1")
    else:
        if agg_result.get("carrier") != "overall_result":
            add("P1A1.RESULT.CARRIER", "statement.predicate.aggregateResult.carrier", "carrier must be overall_result")
        value = agg_result.get("value")
        if value not in ALLOWED_RESULTS:
            add("P1A1.RESULT.VALUE", "statement.predicate.aggregateResult.value", "unsupported result value")
        if isinstance(report, dict) and value != report.get("overall_result"):
            add("P1A1.RESULT.MISMATCH", "statement.predicate.aggregateResult.value", "result does not match transported report")

    boundary = pred.get("claimBoundary")
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_FIELDS:
        add("P1A1.BOUNDARY.FIELD", "statement.predicate.claimBoundary", "claimBoundary fields do not match P1-A1")
    else:
        if boundary.get("authority") != "aggregate_conformance" or boundary.get("transportOnly") is not True:
            add("P1A1.BOUNDARY.MODE", "statement.predicate.claimBoundary", "claimBoundary authority/transportOnly mismatch")
        if boundary.get("doesNotImply") != BOUNDARIES:
            add("P1A1.BOUNDARY.WEAKENED", "statement.predicate.claimBoundary.doesNotImply", "negative implication boundary must match P1-A1 exactly")

    return result(findings)


def re_hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def valid_identity(identity: Any) -> bool:
    return (
        isinstance(identity, dict)
        and set(identity) == {"algorithm", "digest", "bytes"}
        and identity.get("algorithm") == "sha256"
        and isinstance(identity.get("digest"), str)
        and re_hex64(identity["digest"])
        and isinstance(identity.get("bytes"), int)
        and not isinstance(identity.get("bytes"), bool)
        and identity["bytes"] > 0
    )


def result(findings: list[Finding]) -> dict[str, Any]:
    failed = bool(findings)
    return {
        "tool": "eigiib-in-toto-capsule",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if failed else "conformant",
        "findings": [asdict(f) for f in sorted(findings)],
    }


def self_check(root: Path) -> dict[str, Any]:
    findings: list[Finding] = []
    config_path = root / "conformance/p1-a1-in-toto.json"
    agg_path = root / "tests/fixtures/p1-a1/aggregate.json"
    cap_path = root / "tests/fixtures/p1-a1/capsule.json"
    profile_path = root / "conformance/interop-profiles.json"
    for p in (config_path, agg_path, cap_path, profile_path):
        if not p.is_file():
            findings.append(Finding("error", "P1A1.SELF.MISSING", str(p.relative_to(root)), "required file is missing"))
    if findings:
        return result(findings)
    try:
        config = json.loads(config_path.read_text())
        capsule = json.loads(cap_path.read_text())
        profiles = json.loads(profile_path.read_text())
    except Exception as exc:
        return result([Finding("error", "P1A1.SELF.PARSE", "", str(exc))])

    expected_config = {
        "standard": STANDARD,
        "status": "structural-only",
        "profile": PROFILE_ID,
        "external_spec": EXTERNAL_SPEC_ID,
        "statement_type": STATEMENT_TYPE,
        "predicate_type": PREDICATE_TYPE,
        "transport_layer": "statement-only",
        "authentication_state": "not-provided-p1-a1",
        "production_capsules": [],
    }
    if config != expected_config:
        findings.append(Finding("error", "P1A1.SELF.CONFIG", "conformance/p1-a1-in-toto.json", "structural config differs from P1-A1 contract"))

    raw = agg_path.read_bytes()
    expected = build_capsule(raw, "tests/fixtures/p1-a1/aggregate.json")
    if capsule != expected:
        findings.append(Finding("error", "P1A1.SELF.FIXTURE", "tests/fixtures/p1-a1/capsule.json", "checked-in capsule is not deterministic output"))
    vr = validate_capsule(capsule, raw)
    for f in vr["findings"]:
        findings.append(Finding(**f))

    match = None
    for p in profiles.get("profiles", []):
        if isinstance(p, dict) and p.get("id") == PROFILE_ID:
            match = p
            break
    required_evidence = {
        "docs/P1-A1-IN-TOTO-ATTESTATION-CAPSULE.md",
        "tools/eigiib_in_toto_capsule.py",
        "tests/test_eigiib_in_toto_capsule.py",
        "tests/fixtures/p1-a1/aggregate.json",
        "tests/fixtures/p1-a1/capsule.json",
    }
    if not isinstance(match, dict) or match.get("state") != "implemented":
        findings.append(Finding("error", "P1A1.SELF.PROFILE_STATE", "conformance/interop-profiles.json", "M0-A3 in-toto profile must be implemented"))
    elif not required_evidence.issubset(set(match.get("evidence", []))):
        findings.append(Finding("error", "P1A1.SELF.PROFILE_EVIDENCE", "conformance/interop-profiles.json", "M0-A3 profile evidence does not cover P1-A1 adapter"))

    return result(findings)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build")
    b.add_argument("source")
    b.add_argument("--subject-name")
    b.add_argument("-o", "--output")

    v = sub.add_parser("verify")
    v.add_argument("capsule")
    v.add_argument("--source")
    v.add_argument("--json", action="store_true")

    c = sub.add_parser("check")
    c.add_argument("root", nargs="?", default=".")
    c.add_argument("--json", action="store_true")

    args = ap.parse_args()
    if args.command == "build":
        p = Path(args.source)
        raw = p.read_bytes()
        capsule = build_capsule(raw, args.subject_name or str(p))
        text = json.dumps(capsule, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0
    if args.command == "verify":
        capsule = json.loads(Path(args.capsule).read_text(encoding="utf-8"))
        source = Path(args.source).read_bytes() if args.source else None
        out = validate_capsule(capsule, source)
    else:
        out = self_check(Path(args.root).resolve())
    print(json.dumps(out, indent=2, sort_keys=True))
    return 1 if out["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
