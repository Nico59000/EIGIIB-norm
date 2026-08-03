#!/usr/bin/env python3
"""Static EIGIIB-E16-A3 retention, readback and restore checker."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E16-A3-1.0"
MANIFEST_STANDARD = "EIGIIB-E16-A3-AUTHORITY-MANIFEST-1.0"
TRANSITION_STANDARD = "EIGIIB-E16-A3-TRANSITION-1.0"
FREEZE_STANDARD = "EIGIIB-E16-A3-FREEZE-1.0"
HISTORY_STANDARD = "EIGIIB-E16-A3-HISTORICAL-E16-A2-REPLAY-1.0"
PROFILE_REVISION = "EIGIIB-E16-draft-1.0"
SOURCE_E16_A2_HEAD = "1bd5929a5a4415df8758b220765925ac80a797bc"

GATES = {"permit", "deny", "held", "unavailable"}
DECISIONS = {
    "bounded-preservation-and-restore-verified",
    "rejected",
    "held",
    "unavailable",
}
OBSERVATION_STATES = {"positive", "negative", "inconclusive", "unavailable"}
READBACK_STATES = {"positive", "negative", "inconclusive", "unavailable"}
ATTEMPT_STATES = {"completed", "failed", "held", "unavailable"}
VERIFICATION_STATES = {"positive", "negative", "inconclusive", "unavailable"}

EXPECTED_AUTHORITIES = {
    "contract": "extensions/E16-A3-RETENTION-WINDOWS-BOUNDED-PRESERVATION-INDEPENDENT-READBACK-RESTORE-VERIFICATION.md",
    "authority_manifest": "conformance/e16-a3-authority-manifest.json",
    "registry": "conformance/retention-readback-restore.json",
    "transition": "conformance/e16-a3-adoption-transition.json",
    "authority_freeze": "conformance/e16-a3-authority-freeze.json",
    "human_mastery": "docs/E16-A3-HUMAN-MASTERY-GUIDE.md",
    "manual_review": "conformance/E16-A3-MANUAL-REVIEW.md",
    "registry_schema": "schemas/eigiib-e16-a3-retention-readback-restore.schema.json",
    "manifest_schema": "schemas/eigiib-e16-a3-authority-manifest.schema.json",
    "transition_schema": "schemas/eigiib-e16-a3-adoption-transition.schema.json",
    "freeze_schema": "schemas/eigiib-e16-a3-authority-freeze.schema.json",
    "checker": "tools/eigiib_retention_readback_restore_check.py",
    "historical_replay": "tools/eigiib_historical_e16_a2_replay.py",
    "tests": "tests/test_eigiib_retention_readback_restore.py",
    "expected_report": "tests/fixtures/e16-a3/expected-report.json",
    "workflow": ".github/workflows/e16-a3-retention-readback-restore.yml",
}
EXPECTED_FREEZE_PATHS = set(EXPECTED_AUTHORITIES.values()) - {
    "conformance/e16-a3-authority-freeze.json"
}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def commitment_for(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical({key: item for key, item in value.items() if key != "commitment"})
    ).hexdigest()


def combine(values: list[str]) -> str:
    if "deny" in values:
        return "deny"
    if "unavailable" in values:
        return "unavailable"
    if "held" in values:
        return "held"
    return "permit"


def derive_state(gates: dict[str, str]) -> str:
    return {
        "deny": "rejected",
        "unavailable": "unavailable",
        "held": "held",
        "permit": "bounded-preservation-and-restore-verified",
    }[combine(list(gates.values()))]


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed


class Checker:
    def __init__(
        self,
        root: Path,
        registry: Path = Path("conformance/retention-readback-restore.json"),
        manifest: Path = Path("conformance/e16-a3-authority-manifest.json"),
        transition: Path = Path("conformance/e16-a3-adoption-transition.json"),
        freeze: Path = Path("conformance/e16-a3-authority-freeze.json"),
        history_report: Path | None = None,
    ):
        self.root = root.resolve()
        self.registry_path = registry
        self.manifest_path = manifest
        self.transition_path = transition
        self.freeze_path = freeze
        self.history_report_path = history_report
        self.findings: list[Finding] = []
        self.windows: dict[str, dict[str, Any]] = {}
        self.observations: dict[str, dict[str, Any]] = {}
        self.readbacks: dict[str, dict[str, Any]] = {}
        self.attempts: dict[str, dict[str, Any]] = {}
        self.verifications: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.a2_requests: dict[str, dict[str, Any]] = {}
        self.a2_observations: dict[str, dict[str, Any]] = {}
        self.a2_decisions: dict[str, dict[str, Any]] = {}

    def add(self, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding("error", code, path, message))

    @staticmethod
    def nonempty(value: Any) -> bool:
        return isinstance(value, str) and bool(value)

    def confined(self, rel: str, must_exist: bool = True) -> Path | None:
        if not self.nonempty(rel) or Path(rel).is_absolute():
            self.add("E16A3.PATH", "path must be repository-relative", str(rel))
            return None
        path = (self.root / rel).resolve(strict=False)
        try:
            path.relative_to(self.root)
        except ValueError:
            self.add("E16A3.PATH", "path escapes repository root", rel)
            return None
        if must_exist and not path.is_file():
            self.add("E16A3.MISSING", "required file is missing", rel)
            return None
        return path

    def load(self, rel: Path, code: str) -> dict[str, Any] | None:
        path = self.confined(rel.as_posix())
        if path is None:
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add(f"{code}.PARSE", str(exc), rel.as_posix())
            return None
        if not isinstance(value, dict):
            self.add(f"{code}.TYPE", "JSON root must be an object", rel.as_posix())
            return None
        return value

    def index(
        self, obj: dict[str, Any], field: str, code: str
    ) -> dict[str, dict[str, Any]]:
        values = obj.get(field)
        out: dict[str, dict[str, Any]] = {}
        if not isinstance(values, list):
            self.add(f"{code}.TYPE", f"{field} must be an array", field)
            return out
        for idx, value in enumerate(values):
            loc = f"{field}[{idx}]"
            if not isinstance(value, dict) or not self.nonempty(value.get("id")):
                self.add(f"{code}.ITEM", "item requires a non-empty id", loc)
                continue
            if value["id"] in out:
                self.add(f"{code}.DUPLICATE", f"duplicate id {value['id']}", loc)
                continue
            out[value["id"]] = value
        return out

    def check_commitment(self, value: dict[str, Any], path: str) -> None:
        commitment = value.get("commitment")
        if (
            not isinstance(commitment, dict)
            or commitment.get("algorithm") != "sha256"
            or commitment.get("digest") != commitment_for(value)
        ):
            self.add("E16A3.COMMITMENT", "invalid canonical commitment", path)

    def reference(
        self,
        table: dict[str, dict[str, Any]],
        identifier: Any,
        revision: Any,
        commitment: Any,
        code: str,
        path: str,
    ) -> dict[str, Any] | None:
        value = table.get(identifier) if isinstance(identifier, str) else None
        if value is None:
            self.add(code, "referenced record is unavailable", path)
            return None
        if value.get("revision") != revision:
            self.add(code, "referenced revision changed", path)
            return None
        stored = value.get("commitment", {}).get("digest")
        if stored != commitment:
            self.add(code, "referenced commitment changed", path)
            return None
        return value

    def check_manifest(self, manifest: dict[str, Any] | None) -> None:
        if manifest is None:
            return
        if (
            manifest.get("standard") != MANIFEST_STANDARD
            or manifest.get("status") != "authoritative-slice-overlay"
            or manifest.get("profile_revision") != PROFILE_REVISION
            or manifest.get("source_e16_a2_commit") != SOURCE_E16_A2_HEAD
        ):
            self.add(
                "E16A3.MANIFEST.HEADER",
                "authority manifest header is invalid",
                self.manifest_path.as_posix(),
            )
        if manifest.get("required_authorities") != list(EXPECTED_AUTHORITIES):
            self.add(
                "E16A3.MANIFEST.REQUIRED",
                "required authority order changed",
                self.manifest_path.as_posix(),
            )
        if manifest.get("authorities") != EXPECTED_AUTHORITIES:
            self.add(
                "E16A3.MANIFEST.AUTHORITIES",
                "authority bindings changed",
                self.manifest_path.as_posix(),
            )
        for rel in EXPECTED_AUTHORITIES.values():
            self.confined(rel)

    def check_history(self) -> str:
        if self.history_report_path is None:
            self.add(
                "E16A3.HISTORY.MISSING",
                "historical E16-A2 report is required",
            )
            return "non-conformant"
        report = self.load(self.history_report_path, "E16A3.HISTORY")
        if report is None:
            return "non-conformant"
        if (
            report.get("standard") != HISTORY_STANDARD
            or report.get("source_commit") != SOURCE_E16_A2_HEAD
            or report.get("overall_result") != "conformant"
        ):
            self.add(
                "E16A3.HISTORY.RESULT",
                "historical E16-A2 report is not conformant",
                self.history_report_path.as_posix(),
            )
        for key in (
            "e16_a1_history_result",
            "e16_a2_result",
            "e16_a2_tests_result",
        ):
            if report.get(key) != "conformant":
                self.add(
                    "E16A3.HISTORY.COMPONENT",
                    f"{key} is not conformant",
                    self.history_report_path.as_posix(),
                )
        return (
            "non-conformant"
            if any(item.code.startswith("E16A3.HISTORY") for item in self.findings)
            else "conformant"
        )

    def check_transition(self, transition: dict[str, Any] | None) -> None:
        if transition is None:
            return
        if (
            transition.get("standard") != TRANSITION_STANDARD
            or transition.get("status") != "adopted-e16-a3"
        ):
            self.add(
                "E16A3.TRANSITION.HEADER",
                "transition header is invalid",
                self.transition_path.as_posix(),
            )
        source = transition.get("source", {})
        target = transition.get("target", {})
        if (
            source.get("slice") != "E16-A2"
            or source.get("head_commit") != SOURCE_E16_A2_HEAD
            or source.get("profile_revision") != PROFILE_REVISION
            or source.get("authority_freeze")
            != "conformance/e16-a2-authority-freeze.json"
        ):
            self.add(
                "E16A3.TRANSITION.SOURCE",
                "transition source changed",
                self.transition_path.as_posix(),
            )
        if (
            target.get("extension") != "E16-1.0"
            or target.get("slice") != "E16-A3"
            or target.get("profile_revision") != PROFILE_REVISION
            or target.get("authority_manifest")
            != "conformance/e16-a3-authority-manifest.json"
            or target.get("registry")
            != "conformance/retention-readback-restore.json"
        ):
            self.add(
                "E16A3.TRANSITION.TARGET",
                "transition target changed",
                self.transition_path.as_posix(),
            )
        preservation = transition.get("historical_preservation", {})
        expected = {
            "e16_a2_claims_rewritten": False,
            "e16_a2_source_freeze_mutated": False,
            "transition_is_additive": True,
            "descendant_authority_frozen_separately": True,
        }
        if preservation != expected:
            self.add(
                "E16A3.TRANSITION.PRESERVATION",
                "historical preservation declaration changed",
                self.transition_path.as_posix(),
            )

    def check_freeze(self, freeze: dict[str, Any] | None) -> str:
        if freeze is None:
            return "non-conformant"
        if (
            freeze.get("standard") != FREEZE_STANDARD
            or freeze.get("status") != "frozen"
            or freeze.get("profile_revision") != PROFILE_REVISION
            or freeze.get("source_e16_a2_commit") != SOURCE_E16_A2_HEAD
        ):
            self.add(
                "E16A3.FREEZE.HEADER",
                "authority freeze header is invalid",
                self.freeze_path.as_posix(),
            )
        entries = freeze.get("authorities")
        if not isinstance(entries, list):
            self.add(
                "E16A3.FREEZE.TYPE",
                "authorities must be an array",
                self.freeze_path.as_posix(),
            )
            return "non-conformant"
        seen: set[str] = set()
        for idx, entry in enumerate(entries):
            loc = f"authorities[{idx}]"
            if not isinstance(entry, dict) or not self.nonempty(entry.get("path")):
                self.add("E16A3.FREEZE.ITEM", "invalid freeze entry", loc)
                continue
            rel = entry["path"]
            if rel in seen:
                self.add("E16A3.FREEZE.DUPLICATE", "duplicate freeze path", rel)
                continue
            seen.add(rel)
            path = self.confined(rel)
            if path is None:
                continue
            raw = path.read_bytes()
            if entry.get("bytes") != len(raw):
                self.add("E16A3.FREEZE.BYTES", "byte count changed", rel)
            if entry.get("sha256") != hashlib.sha256(raw).hexdigest():
                self.add("E16A3.FREEZE.SHA256", "SHA-256 changed", rel)
        if seen != EXPECTED_FREEZE_PATHS:
            self.add(
                "E16A3.FREEZE.SET",
                "frozen authority set changed",
                self.freeze_path.as_posix(),
            )
        return (
            "non-conformant"
            if any(item.code.startswith("E16A3.FREEZE") for item in self.findings)
            else "conformant"
        )

    @staticmethod
    def state_gate(state: str, positive: str, negative: str) -> str:
        if state == positive:
            return "permit"
        if state == negative:
            return "deny"
        if state == "unavailable":
            return "unavailable"
        return "held"

    def load_upstream(self) -> None:
        upstream = self.load(
            Path("conformance/replica-placement.json"), "E16A3.UPSTREAM"
        )
        if upstream is None:
            return
        if (
            upstream.get("standard") != "EIGIIB-E16-A2-1.0"
            or upstream.get("source_e16_a1_commit")
            != "7fd50a2009c6a437c7fe0b680407cf337b55cf4f"
        ):
            self.add(
                "E16A3.UPSTREAM.HEADER",
                "upstream E16-A2 registry header is invalid",
                "conformance/replica-placement.json",
            )
        self.a2_requests = self.index(
            upstream, "placement_requests", "E16A3.UPSTREAM.REQUEST"
        )
        self.a2_observations = self.index(
            upstream, "placement_observations", "E16A3.UPSTREAM.OBSERVATION"
        )
        self.a2_decisions = self.index(
            upstream, "placement_decisions", "E16A3.UPSTREAM.DECISION"
        )

    def check_window(self, value: dict[str, Any]) -> None:
        path = f"retention_windows[{value.get('id', '?')}]"
        self.check_commitment(value, path)
        decision = self.reference(
            self.a2_decisions,
            value.get("source_placement_decision"),
            value.get("source_placement_decision_revision"),
            value.get("source_placement_decision_commitment"),
            "E16A3.WINDOW.SOURCE",
            path,
        )
        request = self.a2_requests.get(value.get("source_request"))
        if decision is not None:
            if decision.get("state") != "placement-observed":
                self.add(
                    "E16A3.WINDOW.SOURCE.STATE",
                    "source placement decision is not positive",
                    path,
                )
            if (
                decision.get("request") != value.get("source_request")
                or decision.get("request_revision")
                != value.get("source_request_revision")
            ):
                self.add(
                    "E16A3.WINDOW.REQUEST",
                    "source request binding changed",
                    path,
                )
        if request is None:
            self.add(
                "E16A3.WINDOW.REQUEST",
                "source placement request is unavailable",
                path,
            )
        else:
            if (
                request.get("content_sha256") != value.get("content_sha256")
                or request.get("content_bytes") != value.get("content_bytes")
            ):
                self.add(
                    "E16A3.WINDOW.CONTENT",
                    "retention window content identity changed",
                    path,
                )
        start = parse_utc(value.get("not_before"))
        end = parse_utc(value.get("not_after"))
        if start is None or end is None or not start < end:
            self.add(
                "E16A3.WINDOW.TIME",
                "retention window must be an ordered UTC interval",
                path,
            )
        if value.get("opening_observation_required") is not True:
            self.add(
                "E16A3.WINDOW.OPENING",
                "opening observation requirement changed",
                path,
            )
        if value.get("closing_observation_required") is not True:
            self.add(
                "E16A3.WINDOW.CLOSING",
                "closing observation requirement changed",
                path,
            )

    def check_observation(self, value: dict[str, Any]) -> None:
        path = f"preservation_observations[{value.get('id', '?')}]"
        self.check_commitment(value, path)
        window = self.reference(
            self.windows,
            value.get("retention_window"),
            value.get("retention_window_revision"),
            value.get("retention_window_commitment"),
            "E16A3.OBSERVATION.WINDOW",
            path,
        )
        placement = self.a2_observations.get(value.get("placement_observation"))
        if placement is None:
            self.add(
                "E16A3.OBSERVATION.PLACEMENT",
                "source placement observation is unavailable",
                path,
            )
        elif (
            placement.get("revision") != value.get("placement_observation_revision")
            or placement.get("commitment", {}).get("digest")
            != value.get("placement_observation_commitment")
        ):
            self.add(
                "E16A3.OBSERVATION.PLACEMENT",
                "source placement observation binding changed",
                path,
            )
        role = value.get("boundary_role")
        if role not in {"opening", "intermediate", "closing"}:
            self.add(
                "E16A3.OBSERVATION.ROLE",
                "invalid boundary role",
                path,
            )
        observed_at = parse_utc(value.get("observed_at"))
        if observed_at is None:
            self.add(
                "E16A3.OBSERVATION.TIME",
                "observed_at must be UTC",
                path,
            )
        if window is not None and observed_at is not None:
            start = parse_utc(window.get("not_before"))
            end = parse_utc(window.get("not_after"))
            if role == "opening" and observed_at != start:
                self.add(
                    "E16A3.OBSERVATION.OPENING",
                    "opening observation must bind the exact opening boundary",
                    path,
                )
            if role == "closing" and observed_at != end:
                self.add(
                    "E16A3.OBSERVATION.CLOSING",
                    "closing observation must bind the exact closing boundary",
                    path,
                )
            if (
                value.get("observed_content_sha256")
                != window.get("content_sha256")
                or value.get("observed_content_bytes")
                != window.get("content_bytes")
            ):
                self.add(
                    "E16A3.OBSERVATION.CONTENT",
                    "preservation observation content identity changed",
                    path,
                )
        if value.get("observation_state") not in OBSERVATION_STATES:
            self.add(
                "E16A3.OBSERVATION.STATE",
                "invalid observation state",
                path,
            )

    def check_readback(self, value: dict[str, Any]) -> None:
        path = f"independent_readbacks[{value.get('id', '?')}]"
        self.check_commitment(value, path)
        window = self.reference(
            self.windows,
            value.get("retention_window"),
            value.get("retention_window_revision"),
            value.get("retention_window_commitment"),
            "E16A3.READBACK.WINDOW",
            path,
        )
        closing = self.reference(
            self.observations,
            value.get("closing_observation"),
            value.get("closing_observation_revision"),
            value.get("closing_observation_commitment"),
            "E16A3.READBACK.CLOSING",
            path,
        )
        if closing is not None and closing.get("boundary_role") != "closing":
            self.add(
                "E16A3.READBACK.CLOSING",
                "readback must bind a closing observation",
                path,
            )
        reader = value.get("reader", {})
        custodian = value.get("custodian", {})
        if (
            reader.get("id") == custodian.get("id")
            or reader.get("control_domain") == custodian.get("control_domain")
        ):
            self.add(
                "E16A3.READBACK.SEPARATION",
                "reader and custodian require distinct declared identities and control domains",
                path,
            )
        if window is not None and (
            value.get("returned_content_sha256") != window.get("content_sha256")
            or value.get("returned_content_bytes") != window.get("content_bytes")
        ):
            self.add(
                "E16A3.READBACK.CONTENT",
                "readback content identity changed",
                path,
            )
        if value.get("readback_state") not in READBACK_STATES:
            self.add("E16A3.READBACK.STATE", "invalid readback state", path)

    def check_attempt(self, value: dict[str, Any]) -> None:
        path = f"restore_attempts[{value.get('id', '?')}]"
        self.check_commitment(value, path)
        window = self.reference(
            self.windows,
            value.get("retention_window"),
            value.get("retention_window_revision"),
            value.get("retention_window_commitment"),
            "E16A3.RESTORE.WINDOW",
            path,
        )
        readback = self.reference(
            self.readbacks,
            value.get("independent_readback"),
            value.get("independent_readback_revision"),
            value.get("independent_readback_commitment"),
            "E16A3.RESTORE.READBACK",
            path,
        )
        if readback is not None and readback.get("readback_state") != "positive":
            self.add(
                "E16A3.RESTORE.READBACK.STATE",
                "restore attempt requires a positive readback",
                path,
            )
        target = value.get("target_environment", {})
        if target.get("ephemeral") is not True:
            self.add(
                "E16A3.RESTORE.TARGET",
                "restore target must be declared ephemeral",
                path,
            )
        if window is not None and (
            value.get("restored_content_sha256") != window.get("content_sha256")
            or value.get("restored_content_bytes") != window.get("content_bytes")
        ):
            self.add(
                "E16A3.RESTORE.CONTENT",
                "restored content identity changed",
                path,
            )
        if value.get("attempt_state") not in ATTEMPT_STATES:
            self.add("E16A3.RESTORE.STATE", "invalid restore-attempt state", path)

    def check_verification(self, value: dict[str, Any]) -> None:
        path = f"restore_verifications[{value.get('id', '?')}]"
        self.check_commitment(value, path)
        attempt = self.reference(
            self.attempts,
            value.get("restore_attempt"),
            value.get("restore_attempt_revision"),
            value.get("restore_attempt_commitment"),
            "E16A3.VERIFICATION.ATTEMPT",
            path,
        )
        verifier = value.get("verifier", {})
        executor = value.get("executor", {})
        if (
            verifier.get("id") == executor.get("id")
            or verifier.get("control_domain") == executor.get("control_domain")
        ):
            self.add(
                "E16A3.VERIFICATION.SEPARATION",
                "verifier and executor require distinct declared identities and control domains",
                path,
            )
        if attempt is not None and (
            value.get("verified_content_sha256")
            != attempt.get("restored_content_sha256")
            or value.get("verified_content_bytes")
            != attempt.get("restored_content_bytes")
        ):
            self.add(
                "E16A3.VERIFICATION.CONTENT",
                "verified content identity changed",
                path,
            )
        if value.get("verification_state") not in VERIFICATION_STATES:
            self.add(
                "E16A3.VERIFICATION.STATE",
                "invalid restore-verification state",
                path,
            )

    def window_gate(self, window: dict[str, Any] | None) -> str:
        if window is None:
            return "unavailable"
        before = len(self.findings)
        self.check_window(window)
        return "deny" if len(self.findings) > before else "permit"

    def observation_gate(
        self, observation: dict[str, Any] | None, role: str
    ) -> str:
        if observation is None:
            return "unavailable"
        before = len(self.findings)
        self.check_observation(observation)
        if len(self.findings) > before:
            return "deny"
        if observation.get("boundary_role") != role:
            return "deny"
        return self.state_gate(
            observation.get("observation_state"), "positive", "negative"
        )

    def readback_gate(self, readback: dict[str, Any] | None) -> str:
        if readback is None:
            return "unavailable"
        before = len(self.findings)
        self.check_readback(readback)
        if len(self.findings) > before:
            return "deny"
        return self.state_gate(readback.get("readback_state"), "positive", "negative")

    def attempt_gate(self, attempt: dict[str, Any] | None) -> str:
        if attempt is None:
            return "unavailable"
        before = len(self.findings)
        self.check_attempt(attempt)
        if len(self.findings) > before:
            return "deny"
        return self.state_gate(attempt.get("attempt_state"), "completed", "failed")

    def verification_gate(self, verification: dict[str, Any] | None) -> str:
        if verification is None:
            return "unavailable"
        before = len(self.findings)
        self.check_verification(verification)
        if len(self.findings) > before:
            return "deny"
        return self.state_gate(
            verification.get("verification_state"), "positive", "negative"
        )

    def check_decision(self, value: dict[str, Any]) -> None:
        path = f"preservation_verification_decisions[{value.get('id', '?')}]"
        self.check_commitment(value, path)
        window = self.reference(
            self.windows,
            value.get("retention_window"),
            value.get("retention_window_revision"),
            value.get("retention_window_commitment"),
            "E16A3.DECISION.WINDOW",
            path,
        )
        opening = self.reference(
            self.observations,
            value.get("opening_observation"),
            value.get("opening_observation_revision"),
            value.get("opening_observation_commitment"),
            "E16A3.DECISION.OPENING",
            path,
        )
        closing = self.reference(
            self.observations,
            value.get("closing_observation"),
            value.get("closing_observation_revision"),
            value.get("closing_observation_commitment"),
            "E16A3.DECISION.CLOSING",
            path,
        )
        readback = self.reference(
            self.readbacks,
            value.get("independent_readback"),
            value.get("independent_readback_revision"),
            value.get("independent_readback_commitment"),
            "E16A3.DECISION.READBACK",
            path,
        )
        attempt = self.reference(
            self.attempts,
            value.get("restore_attempt"),
            value.get("restore_attempt_revision"),
            value.get("restore_attempt_commitment"),
            "E16A3.DECISION.ATTEMPT",
            path,
        )
        verification = self.reference(
            self.verifications,
            value.get("restore_verification"),
            value.get("restore_verification_revision"),
            value.get("restore_verification_commitment"),
            "E16A3.DECISION.VERIFICATION",
            path,
        )
        placement_gate = "unavailable"
        if window is not None:
            source = self.a2_decisions.get(window.get("source_placement_decision"))
            if source is None:
                placement_gate = "unavailable"
            elif (
                source.get("revision")
                != window.get("source_placement_decision_revision")
                or source.get("commitment", {}).get("digest")
                != window.get("source_placement_decision_commitment")
            ):
                placement_gate = "deny"
            elif source.get("state") == "placement-observed":
                placement_gate = "permit"
            elif source.get("state") == "rejected":
                placement_gate = "deny"
            elif source.get("state") == "unavailable":
                placement_gate = "unavailable"
            else:
                placement_gate = "held"
        derived = {
            "a2_placement": placement_gate,
            "retention_window": self.window_gate(window),
            "opening_observation": self.observation_gate(opening, "opening"),
            "closing_observation": self.observation_gate(closing, "closing"),
            "independent_readback": self.readback_gate(readback),
            "restore_attempt": self.attempt_gate(attempt),
            "restore_verification": self.verification_gate(verification),
        }
        if value.get("gates") != derived:
            self.add(
                "E16A3.DECISION.DERIVATION",
                "stored gates differ from derived gates",
                path,
            )
        state = derive_state(derived)
        if value.get("state") != state:
            self.add(
                "E16A3.DECISION.STATE",
                "stored state differs from derived state",
                path,
            )
        if value.get("state") not in DECISIONS:
            self.add("E16A3.DECISION.STATE", "invalid decision state", path)

    def check_registry(self, registry: dict[str, Any] | None) -> str:
        if registry is None:
            return "non-conformant"
        if (
            registry.get("standard") != STANDARD
            or registry.get("status") != "structural-only"
            or registry.get("source_e16_a2_commit") != SOURCE_E16_A2_HEAD
            or registry.get("upstream_placement_registry")
            != "conformance/replica-placement.json"
            or registry.get("upstream_e16_a2_freeze")
            != "conformance/e16-a2-authority-freeze.json"
            or registry.get("authority_manifest")
            != "conformance/e16-a3-authority-manifest.json"
        ):
            self.add(
                "E16A3.REGISTRY.HEADER",
                "registry header is invalid",
                self.registry_path.as_posix(),
            )
        self.windows = self.index(
            registry, "retention_windows", "E16A3.WINDOW"
        )
        self.observations = self.index(
            registry, "preservation_observations", "E16A3.OBSERVATION"
        )
        self.readbacks = self.index(
            registry, "independent_readbacks", "E16A3.READBACK"
        )
        self.attempts = self.index(
            registry, "restore_attempts", "E16A3.RESTORE"
        )
        self.verifications = self.index(
            registry, "restore_verifications", "E16A3.VERIFICATION"
        )
        self.decisions = self.index(
            registry,
            "preservation_verification_decisions",
            "E16A3.DECISION",
        )
        idempotency: dict[str, str] = {}
        for identifier, window in self.windows.items():
            key = window.get("idempotency_key")
            if not self.nonempty(key):
                self.add(
                    "E16A3.WINDOW.IDEMPOTENCY",
                    "retention window requires an idempotency key",
                    identifier,
                )
            elif key in idempotency:
                self.add(
                    "E16A3.WINDOW.IDEMPOTENCY",
                    f"duplicate idempotency key also used by {idempotency[key]}",
                    identifier,
                )
            else:
                idempotency[key] = identifier
            self.check_window(window)
        for observation in self.observations.values():
            self.check_observation(observation)
        for readback in self.readbacks.values():
            self.check_readback(readback)
        for attempt in self.attempts.values():
            self.check_attempt(attempt)
        for verification in self.verifications.values():
            self.check_verification(verification)
        for decision in self.decisions.values():
            self.check_decision(decision)
        return (
            "non-conformant"
            if any(
                item.code.startswith(
                    (
                        "E16A3.REGISTRY",
                        "E16A3.WINDOW",
                        "E16A3.OBSERVATION",
                        "E16A3.READBACK",
                        "E16A3.RESTORE",
                        "E16A3.VERIFICATION",
                        "E16A3.DECISION",
                        "E16A3.COMMITMENT",
                        "E16A3.UPSTREAM",
                    )
                )
                for item in self.findings
            )
            else "conformant"
        )

    def run(self) -> dict[str, Any]:
        manifest = self.load(self.manifest_path, "E16A3.MANIFEST")
        transition = self.load(self.transition_path, "E16A3.TRANSITION")
        freeze = self.load(self.freeze_path, "E16A3.FREEZE")
        registry = self.load(self.registry_path, "E16A3.REGISTRY")
        self.check_manifest(manifest)
        history_result = self.check_history()
        self.check_transition(transition)
        freeze_result = self.check_freeze(freeze)
        self.load_upstream()
        structural_result = self.check_registry(registry)
        state_counts = {state: 0 for state in sorted(DECISIONS)}
        for decision in self.decisions.values():
            state = decision.get("state")
            if state in state_counts:
                state_counts[state] += 1
        verification_result = (
            "not-evaluated"
            if not self.decisions and structural_result == "conformant"
            else (
                "conformant"
                if structural_result == "conformant"
                and history_result == "conformant"
                and freeze_result == "conformant"
                else "non-conformant"
            )
        )
        return {
            "tool": "eigiib-retention-readback-restore-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "historical_continuity_result": history_result,
            "authority_freeze_result": freeze_result,
            "structural_result": structural_result,
            "verification_result": verification_result,
            "retention_window_count": len(self.windows),
            "preservation_observation_count": len(self.observations),
            "independent_readback_count": len(self.readbacks),
            "restore_attempt_count": len(self.attempts),
            "restore_verification_count": len(self.verifications),
            "preservation_verification_decision_count": len(self.decisions),
            "decision_state_counts": state_counts,
            "findings": [asdict(item) for item in sorted(self.findings)],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--registry",
        default="conformance/retention-readback-restore.json",
    )
    parser.add_argument(
        "--manifest",
        default="conformance/e16-a3-authority-manifest.json",
    )
    parser.add_argument(
        "--transition",
        default="conformance/e16-a3-adoption-transition.json",
    )
    parser.add_argument(
        "--freeze",
        default="conformance/e16-a3-authority-freeze.json",
    )
    parser.add_argument("--history-report")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    checker = Checker(
        Path(args.root),
        Path(args.registry),
        Path(args.manifest),
        Path(args.transition),
        Path(args.freeze),
        Path(args.history_report) if args.history_report else None,
    )
    report = checker.run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not report["findings"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
