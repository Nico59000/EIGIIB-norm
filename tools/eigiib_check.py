#!/usr/bin/env python3
"""EIGIIB-E2 repository conformance checker.

Static by design: no network access, no repository command execution, no imports
from the target repository. Python 3.11+ is required for tomllib.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover - version guard
    tomllib = None

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0"
KNOWN_TOP = {
    "standard",
    "extensions",
    "conformance_target",
    "revision",
    "registry",
    "ownership_registry",
    "authorities",
    "required_authorities",
    "checks",
    "manual_gates",
}
TARGETS = {"EIGIIB-C1", "EIGIIB-C2", "EIGIIB-C3"}
CLAIM_STATES = {
    "established",
    "partially-established",
    "contested",
    "refuted",
    "not-evaluated",
    "unavailable",
    "not-applicable",
}
EVIDENCE_RESULTS = {
    "pass",
    "fail",
    "inconclusive",
    "not-run",
    "unavailable",
    "not-applicable",
}
SCOPE_RULES = {"exact", "evidence-superset", "manual"}
MANUAL_STATES = {"complete", "pending", "not-applicable"}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
MD_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Checker:
    def __init__(self, root: Path, config_path: Path):
        self.root = root.resolve()
        self.config_path = config_path
        self.findings: list[Finding] = []
        self.config: dict[str, Any] = {}
        self.authorities: dict[str, str] = {}
        self.manual_pending = False
        self.manual_seen = False

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def safe_path(
        self,
        raw: str,
        *,
        must_exist: bool = True,
        file_only: bool = True,
    ) -> Path | None:
        if not isinstance(raw, str) or not raw:
            self.add(
                "error",
                "M-PATH.INVALID",
                "path must be a non-empty string",
                str(raw),
            )
            return None
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add(
                "error",
                "M-PATH.ESCAPE",
                "absolute or parent-escaping path is forbidden",
                raw,
            )
            return None
        candidate = (self.root / p).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add(
                "error",
                "M-PATH.ESCAPE",
                "resolved path escapes repository root",
                raw,
            )
            return None
        if must_exist and not candidate.exists():
            self.add(
                "error",
                "M-PATH.MISSING",
                "configured path does not exist",
                raw,
            )
            return None
        if must_exist and file_only and not candidate.is_file():
            self.add(
                "error",
                "M-PATH.TYPE",
                "configured path is not a regular file",
                raw,
            )
            return None
        if must_exist:
            try:
                real = candidate.resolve(strict=True)
                real.relative_to(self.root)
            except (OSError, ValueError):
                self.add(
                    "error",
                    "M-PATH.SYMLINK",
                    "path cannot be safely resolved inside repository",
                    raw,
                )
                return None
        return candidate

    def load_profile(self) -> bool:
        if tomllib is None:
            self.add(
                "error",
                "TOOL.PYTHON",
                "Python 3.11+ is required for tomllib",
            )
            return False
        cfg = self.safe_path(str(self.config_path), must_exist=True)
        if cfg is None:
            return False
        try:
            self.config = tomllib.loads(cfg.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            self.add(
                "error",
                "M-PROFILE.PARSE",
                f"cannot parse TOML profile: {exc}",
                str(self.config_path),
            )
            return False

        unknown = sorted(set(self.config) - KNOWN_TOP)
        for key in unknown:
            self.add(
                "error",
                "M-PROFILE.UNKNOWN",
                f"unknown top-level key: {key}",
                str(self.config_path),
            )

        if self.config.get("standard") != "EIGIIB-1.0":
            self.add(
                "error",
                "M-PROFILE.STANDARD",
                "standard must be EIGIIB-1.0",
                str(self.config_path),
            )

        extensions = self.config.get("extensions")
        if not isinstance(extensions, list) or not all(
            isinstance(x, str) for x in extensions
        ):
            self.add(
                "error",
                "M-PROFILE.EXTENSIONS",
                "extensions must be a string array",
                str(self.config_path),
            )
        else:
            for needed in ("E1-1.0", "E2-1.0"):
                if needed not in extensions:
                    self.add(
                        "error",
                        "M-PROFILE.EXTENSIONS",
                        f"required extension missing: {needed}",
                        str(self.config_path),
                    )

        target = self.config.get("conformance_target")
        if target not in TARGETS:
            self.add(
                "error",
                "M-PROFILE.TARGET",
                "invalid conformance_target",
                str(self.config_path),
            )

        revision = self.config.get("revision")
        if not isinstance(revision, str) or not revision.strip():
            self.add(
                "error",
                "M-PROFILE.REVISION",
                "revision must be a non-empty string",
                str(self.config_path),
            )

        authorities = self.config.get("authorities", {})
        if not isinstance(authorities, dict) or not authorities:
            self.add(
                "error",
                "M-AUTH.EMPTY",
                "authorities must be a non-empty table",
                str(self.config_path),
            )
            authorities = {}

        self.authorities = {}
        for role in sorted(authorities):
            raw = authorities[role]
            if (
                not isinstance(role, str)
                or not role
                or not isinstance(raw, str)
            ):
                self.add(
                    "error",
                    "M-AUTH.TYPE",
                    "authority roles and paths must be strings",
                    str(self.config_path),
                )
                continue
            if self.safe_path(raw) is not None:
                self.authorities[role] = raw

        required = self.config.get("required_authorities", [])
        if not isinstance(required, list) or not all(
            isinstance(x, str) for x in required
        ):
            self.add(
                "error",
                "M-AUTH.REQUIRED",
                "required_authorities must be a string array",
                str(self.config_path),
            )
        else:
            for role in sorted(set(required)):
                if role not in self.authorities:
                    self.add(
                        "error",
                        "M-AUTH.MISSING",
                        f"required authority is not declared or unresolved: {role}",
                    )
        return True

    def load_json(self, raw_path: str, code: str) -> dict[str, Any] | None:
        p = self.safe_path(raw_path)
        if p is None:
            return None
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.add(
                "error",
                f"{code}.PARSE",
                f"cannot parse JSON: {exc}",
                raw_path,
            )
            return None
        if not isinstance(obj, dict):
            self.add(
                "error",
                f"{code}.TYPE",
                "registry root must be a JSON object",
                raw_path,
            )
            return None
        return obj

    def check_ownership(self) -> None:
        raw = self.config.get("ownership_registry")
        if raw is None:
            return
        if not isinstance(raw, str):
            self.add(
                "error",
                "M-OWN.PATH",
                "ownership_registry must be a path string",
            )
            return
        obj = self.load_json(raw, "M-OWN")
        if obj is None:
            return
        if obj.get("standard") != "EIGIIB-1.0+E2-1.0":
            self.add(
                "error",
                "M-OWN.STANDARD",
                "ownership registry has unsupported standard",
                raw,
            )
        facts = obj.get("facts")
        if not isinstance(facts, list):
            self.add("error", "M-OWN.FACTS", "facts must be an array", raw)
            return
        seen: set[str] = set()
        for i, item in enumerate(facts):
            loc = f"{raw}#/facts/{i}"
            if not isinstance(item, dict):
                self.add(
                    "error",
                    "M-OWN.ITEM",
                    "fact record must be an object",
                    loc,
                )
                continue
            fid = item.get("id")
            authority = item.get("authority")
            if not isinstance(fid, str) or not ID_RE.fullmatch(fid):
                self.add("error", "M-OWN.ID", "invalid fact id", loc)
                continue
            if fid in seen:
                self.add(
                    "error",
                    "M-OWN.DUPLICATE",
                    f"duplicate durable fact owner: {fid}",
                    loc,
                )
            seen.add(fid)
            if (
                not isinstance(authority, str)
                or authority not in self.authorities
            ):
                self.add(
                    "error",
                    "M-OWN.AUTHORITY",
                    f"unresolved authority role: {authority}",
                    loc,
                )

    @staticmethod
    def scope_valid(scope: Any) -> bool:
        if not isinstance(scope, dict):
            return False
        for dim, vals in scope.items():
            if not isinstance(dim, str) or not dim:
                return False
            if (
                not isinstance(vals, list)
                or not vals
                or not all(isinstance(v, str) and v for v in vals)
            ):
                return False
            if len(vals) != len(set(vals)):
                return False
        return True

    @staticmethod
    def scope_covers(
        evidence_scope: dict[str, list[str]],
        claim_scope: dict[str, list[str]],
        rule: str,
    ) -> bool:
        if rule == "exact":
            return evidence_scope == claim_scope
        if rule == "manual":
            return False
        if rule != "evidence-superset":
            return False
        # Extra evidence dimensions narrow an observation and cannot prove a
        # claim that intentionally leaves those dimensions unconstrained.
        if set(evidence_scope) != set(claim_scope):
            return False
        for dim, claim_values in claim_scope.items():
            if not set(claim_values).issubset(
                set(evidence_scope.get(dim, []))
            ):
                return False
        return True

    def check_e1_registry(self) -> None:
        raw = self.config.get("registry")
        target = self.config.get("conformance_target")
        if raw is None:
            if target in {"EIGIIB-C2", "EIGIIB-C3"}:
                self.add(
                    "warning",
                    "M-E1.ABSENT",
                    "C2/C3 profile has no typed claim/evidence registry",
                )
            return
        if not isinstance(raw, str):
            self.add("error", "M-E1.PATH", "registry must be a path string")
            return
        obj = self.load_json(raw, "M-E1")
        if obj is None:
            return
        if obj.get("standard") != "EIGIIB-1.0+E1-1.0":
            self.add(
                "error",
                "M-E1.STANDARD",
                "registry standard must be EIGIIB-1.0+E1-1.0",
                raw,
            )

        policies = obj.get("policies")
        claims = obj.get("claims")
        evidence = obj.get("evidence")
        if (
            not isinstance(policies, list)
            or not isinstance(claims, list)
            or not isinstance(evidence, list)
        ):
            self.add(
                "error",
                "M-E1.COLLECTIONS",
                "policies, claims, and evidence must be arrays",
                raw,
            )
            return

        policy_map: dict[str, dict[str, Any]] = {}
        evidence_map: dict[str, dict[str, Any]] = {}
        claim_ids: set[str] = set()

        for i, policy in enumerate(policies):
            loc = f"{raw}#/policies/{i}"
            if not isinstance(policy, dict):
                self.add(
                    "error",
                    "M-E1.POLICY",
                    "policy must be an object",
                    loc,
                )
                continue
            pid = policy.get("id")
            if not isinstance(pid, str) or not ID_RE.fullmatch(pid):
                self.add(
                    "error",
                    "M-E1.POLICY_ID",
                    "invalid policy id",
                    loc,
                )
                continue
            if pid in policy_map:
                self.add(
                    "error",
                    "M-E1.DUPLICATE",
                    f"duplicate policy id: {pid}",
                    loc,
                )
            policy_map[pid] = policy
            kinds = policy.get("required_kinds")
            if not isinstance(kinds, list) or not all(
                isinstance(k, str) and ID_RE.fullmatch(k) for k in kinds
            ):
                self.add(
                    "error",
                    "M-E1.POLICY_KINDS",
                    "required_kinds must be valid id strings",
                    loc,
                )
            rule = policy.get("scope_rule")
            if rule not in SCOPE_RULES:
                self.add(
                    "error",
                    "M-E1.SCOPE_RULE",
                    f"unsupported scope_rule: {rule}",
                    loc,
                )

        for i, ev in enumerate(evidence):
            loc = f"{raw}#/evidence/{i}"
            if not isinstance(ev, dict):
                self.add(
                    "error",
                    "M-E1.EVIDENCE",
                    "evidence must be an object",
                    loc,
                )
                continue
            eid = ev.get("id")
            if not isinstance(eid, str) or not ID_RE.fullmatch(eid):
                self.add(
                    "error",
                    "M-E1.EVIDENCE_ID",
                    "invalid evidence id",
                    loc,
                )
                continue
            if eid in evidence_map:
                self.add(
                    "error",
                    "M-E1.DUPLICATE",
                    f"duplicate evidence id: {eid}",
                    loc,
                )
            evidence_map[eid] = ev
            if ev.get("result") not in EVIDENCE_RESULTS:
                self.add(
                    "error",
                    "M-E1.EVIDENCE_RESULT",
                    f"invalid evidence result: {ev.get('result')}",
                    loc,
                )
            if not self.scope_valid(ev.get("scope")):
                self.add(
                    "error",
                    "M-E1.EVIDENCE_SCOPE",
                    "invalid evidence scope",
                    loc,
                )
            artifacts = ev.get("artifacts", [])
            if not isinstance(artifacts, list) or not all(
                isinstance(a, str) for a in artifacts
            ):
                self.add(
                    "error",
                    "M-E1.ARTIFACTS",
                    "artifacts must be a string array",
                    loc,
                )
            else:
                for artifact in artifacts:
                    self.safe_path(artifact)

        for i, claim in enumerate(claims):
            loc = f"{raw}#/claims/{i}"
            if not isinstance(claim, dict):
                self.add(
                    "error",
                    "M-E1.CLAIM",
                    "claim must be an object",
                    loc,
                )
                continue
            cid = claim.get("id")
            if not isinstance(cid, str) or not ID_RE.fullmatch(cid):
                self.add(
                    "error",
                    "M-E1.CLAIM_ID",
                    "invalid claim id",
                    loc,
                )
                continue
            if cid in claim_ids:
                self.add(
                    "error",
                    "M-E1.DUPLICATE",
                    f"duplicate claim id: {cid}",
                    loc,
                )
            claim_ids.add(cid)

            state = claim.get("state")
            if state not in CLAIM_STATES:
                self.add(
                    "error",
                    "M-E1.CLAIM_STATE",
                    f"invalid claim state: {state}",
                    loc,
                )
            if not self.scope_valid(claim.get("scope")):
                self.add(
                    "error",
                    "M-E1.CLAIM_SCOPE",
                    "invalid claim scope",
                    loc,
                )
            authority = claim.get("authority")
            if (
                not isinstance(authority, str)
                or authority not in self.authorities
            ):
                self.add(
                    "error",
                    "M-E1.CLAIM_AUTHORITY",
                    f"unresolved claim authority: {authority}",
                    loc,
                )

            pid = claim.get("policy")
            policy = policy_map.get(pid) if isinstance(pid, str) else None
            if policy is None:
                self.add(
                    "error",
                    "M-E1.CLAIM_POLICY",
                    f"unresolved policy: {pid}",
                    loc,
                )
                continue

            refs = claim.get("evidence", [])
            if not isinstance(refs, list) or not all(
                isinstance(x, str) for x in refs
            ):
                self.add(
                    "error",
                    "M-E1.CLAIM_EVIDENCE",
                    "claim evidence must be a string array",
                    loc,
                )
                continue

            records: list[dict[str, Any]] = []
            for ref in refs:
                ev = evidence_map.get(ref)
                if ev is None:
                    self.add(
                        "error",
                        "M-E1.DANGLING",
                        f"dangling evidence reference: {ref}",
                        loc,
                    )
                else:
                    records.append(ev)
            self.evaluate_claim(claim, policy, records, loc)

    def evaluate_claim(
        self,
        claim: dict[str, Any],
        policy: dict[str, Any],
        records: list[dict[str, Any]],
        loc: str,
    ) -> None:
        if claim.get("state") != "established":
            return

        rule = policy.get("scope_rule")
        gates = policy.get("manual_gates", [])
        if rule == "manual" or gates:
            completed = self.completed_manual_gate_ids()
            missing = [gate for gate in gates if gate not in completed]
            if rule == "manual" and not gates:
                self.add(
                    "error",
                    "M-STATE.MANUAL",
                    "established manual policy has no declared manual gate",
                    loc,
                )
            for gate in missing:
                self.add(
                    "error",
                    "M-STATE.MANUAL",
                    f"required manual gate is not complete: {gate}",
                    loc,
                )
            if rule == "manual":
                return

        required = policy.get("required_kinds", [])
        if not isinstance(required, list):
            return

        claim_scope = claim.get("scope")
        subject = claim.get("subject")
        revision = claim.get("revision")
        satisfied: set[str] = set()

        for ev in records:
            if ev.get("subject") != subject or ev.get("revision") != revision:
                continue
            if (
                not isinstance(claim_scope, dict)
                or not isinstance(ev.get("scope"), dict)
            ):
                continue
            overlaps = self.scopes_overlap(ev["scope"], claim_scope)
            if ev.get("result") == "fail" and overlaps:
                self.add(
                    "error",
                    "M-STATE.CONTRADICTION",
                    "established claim references failing evidence: "
                    f"{ev.get('id')}",
                    loc,
                )
            if ev.get("result") != "pass":
                continue
            if not self.scope_covers(ev["scope"], claim_scope, rule):
                continue
            kind = ev.get("kind")
            if isinstance(kind, str):
                satisfied.add(kind)

        for kind in required:
            if kind not in satisfied:
                self.add(
                    "error",
                    "M-STATE.UNSATISFIED",
                    "established claim lacks satisfying evidence kind: "
                    f"{kind}",
                    loc,
                )

    @staticmethod
    def scopes_overlap(
        a: dict[str, list[str]],
        b: dict[str, list[str]],
    ) -> bool:
        shared = set(a) & set(b)
        if not shared:
            return False
        return all(set(a[dim]) & set(b[dim]) for dim in shared)

    def completed_manual_gate_ids(self) -> set[str]:
        result: set[str] = set()
        gates = self.config.get("manual_gates", [])
        if not isinstance(gates, list):
            return result
        for gate in gates:
            if (
                isinstance(gate, dict)
                and gate.get("status") == "complete"
                and isinstance(gate.get("id"), str)
            ):
                result.add(gate["id"])
        return result

    def check_manual_gates(self) -> None:
        gates = self.config.get("manual_gates", [])
        if not isinstance(gates, list):
            self.add(
                "error",
                "M-MANUAL.TYPE",
                "manual_gates must be an array of tables",
            )
            return
        seen: set[str] = set()
        for i, gate in enumerate(gates):
            self.manual_seen = True
            loc = f"EIGIIB.toml#manual_gates/{i}"
            if not isinstance(gate, dict):
                self.add(
                    "error",
                    "M-MANUAL.ITEM",
                    "manual gate must be a table",
                    loc,
                )
                continue
            gid = gate.get("id")
            status = gate.get("status")
            authority = gate.get("authority")
            if not isinstance(gid, str) or not ID_RE.fullmatch(gid):
                self.add(
                    "error",
                    "M-MANUAL.ID",
                    "invalid manual gate id",
                    loc,
                )
                continue
            if gid in seen:
                self.add(
                    "error",
                    "M-MANUAL.DUPLICATE",
                    f"duplicate manual gate id: {gid}",
                    loc,
                )
            seen.add(gid)
            if status not in MANUAL_STATES:
                self.add(
                    "error",
                    "M-MANUAL.STATUS",
                    f"invalid manual gate status: {status}",
                    loc,
                )
                continue
            if (
                not isinstance(authority, str)
                or authority not in self.authorities
            ):
                self.add(
                    "error",
                    "M-MANUAL.AUTHORITY",
                    f"unresolved manual gate authority: {authority}",
                    loc,
                )
            if status == "pending":
                self.manual_pending = True
                self.add(
                    "info",
                    "M-MANUAL.PENDING",
                    f"manual gate remains pending: {gid}",
                    loc,
                )
            if status == "complete":
                attestation = gate.get("attestation")
                if (
                    not isinstance(attestation, str)
                    or self.safe_path(attestation) is None
                ):
                    self.add(
                        "error",
                        "M-MANUAL.ATTESTATION",
                        "complete gate requires an existing attestation: "
                        f"{gid}",
                        loc,
                    )

    def check_markdown_links(self) -> None:
        checks = self.config.get("checks", {})
        if not isinstance(checks, dict):
            self.add(
                "error",
                "M-PROFILE.CHECKS",
                "checks must be a table",
            )
            return
        enabled = checks.get("markdown_links", False)
        if not isinstance(enabled, bool):
            self.add(
                "error",
                "M-PROFILE.CHECKS",
                "checks.markdown_links must be boolean",
            )
            return
        if not enabled:
            return

        files = sorted(
            p for p in self.root.rglob("*.md") if ".git" not in p.parts
        )
        for md in files:
            try:
                text = md.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                self.add(
                    "error",
                    "M-LINK.READ",
                    f"cannot read Markdown: {exc}",
                    str(md.relative_to(self.root)),
                )
                continue
            for raw_target in MD_LINK_RE.findall(text):
                target = raw_target.strip().split()[0].strip("<>")
                if not target or target.startswith(
                    ("http://", "https://", "mailto:", "#", "data:")
                ):
                    continue
                path_part = target.split("#", 1)[0]
                if not path_part:
                    continue
                decoded = path_part.replace("%20", " ")
                candidate = Path(decoded)
                if candidate.is_absolute() or ".." in candidate.parts:
                    self.add(
                        "error",
                        "M-LINK.ESCAPE",
                        f"local Markdown link escapes repository: {target}",
                        str(md.relative_to(self.root)),
                    )
                    continue
                resolved = (md.parent / candidate).resolve(strict=False)
                try:
                    resolved.relative_to(self.root)
                except ValueError:
                    self.add(
                        "error",
                        "M-LINK.ESCAPE",
                        f"local Markdown link escapes repository: {target}",
                        str(md.relative_to(self.root)),
                    )
                    continue
                if not resolved.exists():
                    self.add(
                        "error",
                        "M-LINK.MISSING",
                        f"broken local Markdown link: {target}",
                        str(md.relative_to(self.root)),
                    )

    def run(self) -> dict[str, Any]:
        loaded = self.load_profile()
        if loaded:
            self.check_manual_gates()
            self.check_ownership()
            self.check_e1_registry()
            self.check_markdown_links()

        findings = sorted(
            self.findings,
            key=lambda finding: (
                finding.severity,
                finding.code,
                finding.path,
                finding.message,
            ),
        )
        errors = sum(finding.severity == "error" for finding in findings)
        mechanical = "non-conformant" if errors else "conformant"
        manual = (
            "pending"
            if self.manual_pending
            else ("complete" if self.manual_seen else "not-applicable")
        )

        if mechanical == "non-conformant":
            overall = "non-conformant"
        elif manual == "pending":
            overall = "partially-evaluated"
        else:
            overall = "conformant"

        return {
            "tool": "eigiib-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "target": self.config.get("conformance_target", "unknown"),
            "revision": self.config.get("revision", "unknown"),
            "mechanical_result": mechanical,
            "manual_result": manual,
            "overall_result": overall,
            "findings": [asdict(finding) for finding in findings],
        }


def exit_code(report: dict[str, Any]) -> int:
    if report["mechanical_result"] == "non-conformant":
        return 1
    if report["overall_result"] == "partially-evaluated":
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check EIGIIB-E2 repository conformance without executing "
            "repository code."
        )
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="repository root",
    )
    parser.add_argument(
        "--config",
        default="EIGIIB.toml",
        help="profile path relative to root",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit deterministic JSON report",
    )
    args = parser.parse_args(argv)

    if sys.version_info < (3, 11):
        print("eigiib-check requires Python 3.11+", file=sys.stderr)
        return 3

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"repository root is not a directory: {root}", file=sys.stderr)
        return 64

    config = Path(args.config)
    if config.is_absolute() or ".." in config.parts:
        print(
            "--config must be a repository-relative non-escaping path",
            file=sys.stderr,
        )
        return 64

    checker = Checker(root, config)
    report = checker.run()

    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(f"EIGIIB target: {report['target']}")
        print(f"mechanical: {report['mechanical_result']}")
        print(f"manual:     {report['manual_result']}")
        print(f"overall:    {report['overall_result']}")
        for finding in report["findings"]:
            where = f" [{finding['path']}]" if finding["path"] else ""
            print(
                f"{finding['severity'].upper():7} "
                f"{finding['code']}{where}: {finding['message']}"
            )

    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
