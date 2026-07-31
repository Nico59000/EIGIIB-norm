#!/usr/bin/env python3
"""Static EIGIIB-E3 provenance and artifact-identity checker.

The checker reads repository metadata and hashes declared local artifacts.
It performs no network access and executes no repository-provided commands.
Python 3.11+ is required for tomllib.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVENT_RESULTS = {"success", "failure", "inconclusive", "not-run", "unavailable"}
REPLAY_RELATIONS = {
    "byte-exact",
    "canonical-equivalent",
    "semantic-equivalent",
    "observation-only",
}
REPLAY_RESULTS = {
    "match",
    "mismatch",
    "inconclusive",
    "not-run",
    "unavailable",
    "not-applicable",
}
INDEPENDENCE = {
    "same-executor",
    "separate-run",
    "separate-environment",
    "separate-implementation",
    "external-party",
    "unknown",
}
DETERMINISM = {
    "deterministic",
    "conditionally-deterministic",
    "nondeterministic",
    "unknown",
}
AVAILABILITY = {"local", "external", "unavailable"}
IDENTITY_STATES = {"verified", "declared", "unavailable"}


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
        self.registry_path: str | None = None
        self.registry: dict[str, Any] = {}

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def safe_path(self, raw: str, *, must_exist: bool = True) -> Path | None:
        if not isinstance(raw, str) or not raw:
            self.add("error", "M-E3-PATH.INVALID", "path must be a non-empty string", str(raw))
            return None
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error", "M-E3-PATH.ESCAPE", "absolute or parent-escaping path is forbidden", raw)
            return None
        candidate = (self.root / p).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("error", "M-E3-PATH.ESCAPE", "resolved path escapes repository root", raw)
            return None
        if must_exist and not candidate.exists():
            self.add("error", "M-E3-PATH.MISSING", "configured path does not exist", raw)
            return None
        if must_exist and not candidate.is_file():
            self.add("error", "M-E3-PATH.TYPE", "configured path is not a regular file", raw)
            return None
        if must_exist:
            try:
                real = candidate.resolve(strict=True)
                real.relative_to(self.root)
            except (OSError, ValueError):
                self.add("error", "M-E3-PATH.SYMLINK", "path cannot be safely resolved inside repository", raw)
                return None
        return candidate

    def load_profile(self) -> bool:
        if tomllib is None:
            self.add("error", "TOOL.PYTHON", "Python 3.11+ is required for tomllib")
            return False
        p = self.safe_path(str(self.config_path))
        if p is None:
            return False
        try:
            self.config = tomllib.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            self.add("error", "M-E3-PROFILE.PARSE", f"cannot parse TOML profile: {exc}", str(self.config_path))
            return False
        extensions = self.config.get("extensions")
        if not isinstance(extensions, list) or "E3-1.0" not in extensions:
            self.add("error", "M-E3-PROFILE.EXTENSION", "E3-1.0 must be declared in EIGIIB.toml", str(self.config_path))
        auth = self.config.get("authorities", {})
        if not isinstance(auth, dict):
            self.add("error", "M-E3-PROFILE.AUTHORITY", "authorities must be a table", str(self.config_path))
            return False
        self.authorities = {k: v for k, v in auth.items() if isinstance(k, str) and isinstance(v, str)}
        raw = self.authorities.get("provenance")
        if raw is None:
            self.add("error", "M-E3-PROFILE.AUTHORITY", "authorities.provenance is required", str(self.config_path))
            return False
        self.registry_path = raw
        if self.safe_path(raw) is None:
            return False
        return True

    def load_registry(self) -> bool:
        assert self.registry_path is not None
        p = self.safe_path(self.registry_path)
        if p is None:
            return False
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.add("error", "M-E3-REGISTRY.PARSE", f"cannot parse provenance registry: {exc}", self.registry_path)
            return False
        if not isinstance(obj, dict):
            self.add("error", "M-E3-REGISTRY.TYPE", "provenance registry root must be an object", self.registry_path)
            return False
        self.registry = obj
        if obj.get("standard") != STANDARD:
            self.add("error", "M-E3-REGISTRY.STANDARD", f"registry standard must be {STANDARD}", self.registry_path)
        revision = obj.get("revision")
        if not isinstance(revision, str) or not revision:
            self.add("error", "M-E3-REGISTRY.REVISION", "registry revision must be a non-empty string", self.registry_path)
        for name in ("artifacts", "environments", "equivalence_policies", "procedures", "events", "replays", "evidence_bindings"):
            if not isinstance(obj.get(name), list):
                self.add("error", "M-E3-REGISTRY.COLLECTION", f"{name} must be an array", self.registry_path)
                return False
        return True

    @staticmethod
    def valid_id(value: Any) -> bool:
        return isinstance(value, str) and bool(ID_RE.fullmatch(value))

    def index_collection(self, name: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        items = self.registry.get(name, [])
        for i, item in enumerate(items):
            loc = f"{self.registry_path}#/{name}/{i}"
            if not isinstance(item, dict):
                self.add("error", "M-E3-REGISTRY.ITEM", f"{name} item must be an object", loc)
                continue
            iid = item.get("id")
            if not self.valid_id(iid):
                self.add("error", "M-E3-REGISTRY.ID", f"invalid {name} id", loc)
                continue
            if iid in result:
                self.add("error", "M-E3-REGISTRY.DUPLICATE", f"duplicate {name} id: {iid}", loc)
            result[iid] = item
        return result

    def check_artifacts(self, artifacts: dict[str, dict[str, Any]]) -> None:
        for aid, item in artifacts.items():
            loc = f"{self.registry_path}#/artifacts/{aid}"
            role = item.get("role")
            if not isinstance(role, str) or not role:
                self.add("error", "M-E3-ARTIFACT.ROLE", "artifact role must be non-empty", loc)
            availability = item.get("availability")
            state = item.get("identity_state")
            if availability not in AVAILABILITY:
                self.add("error", "M-E3-ARTIFACT.AVAILABILITY", f"invalid availability: {availability}", loc)
            if state not in IDENTITY_STATES:
                self.add("error", "M-E3-ARTIFACT.STATE", f"invalid identity_state: {state}", loc)

            digests = item.get("digests", {})
            if digests is not None and not isinstance(digests, dict):
                self.add("error", "M-E3-ARTIFACT.DIGESTS", "digests must be an object", loc)
                digests = {}
            sha = digests.get("sha256") if isinstance(digests, dict) else None
            if sha is not None and (not isinstance(sha, str) or not SHA256_RE.fullmatch(sha)):
                self.add("error", "M-E3-ARTIFACT.SHA256", "sha256 must be 64 lowercase hexadecimal characters", loc)

            if availability == "local":
                raw = item.get("path")
                if not isinstance(raw, str):
                    self.add("error", "M-E3-ARTIFACT.PATH", "local artifact requires path", loc)
                    continue
                if self.registry_path is not None and Path(raw) == Path(self.registry_path):
                    self.add("error", "M-E3-ARTIFACT.SELF", "provenance registry cannot claim normative identity of its own bytes", loc)
                    continue
                p = self.safe_path(raw)
                if p is None:
                    continue
                declared_size = item.get("size")
                if not isinstance(declared_size, int) or declared_size < 0:
                    self.add("error", "M-E3-ARTIFACT.SIZE", "local artifact requires non-negative integer size", loc)
                else:
                    actual_size = p.stat().st_size
                    if actual_size != declared_size:
                        self.add("error", "M-E3-ARTIFACT.SIZE", f"size mismatch: declared {declared_size}, observed {actual_size}", loc)
                if not isinstance(sha, str) or not SHA256_RE.fullmatch(sha):
                    self.add("error", "M-E3-ARTIFACT.SHA256", "local artifact requires supported sha256 digest", loc)
                else:
                    actual = hashlib.sha256(p.read_bytes()).hexdigest()
                    if actual != sha:
                        self.add("error", "M-E3-ARTIFACT.MISMATCH", f"sha256 mismatch for {aid}", raw)
                if state == "unavailable":
                    self.add("error", "M-E3-ARTIFACT.STATE", "local artifact cannot declare identity_state unavailable", loc)
            elif state == "verified":
                self.add("error", "M-E3-ARTIFACT.VERIFICATION", "non-local artifact cannot be locally verified by static E3 checker", loc)

    def check_environments(
        self,
        environments: dict[str, dict[str, Any]],
        artifacts: dict[str, dict[str, Any]],
    ) -> None:
        for eid, env in environments.items():
            loc = f"{self.registry_path}#/environments/{eid}"
            props = env.get("properties")
            if not isinstance(props, dict):
                self.add("error", "M-E3-ENV.PROPERTIES", "environment properties must be an object", loc)
            refs = env.get("artifact_refs", [])
            if not isinstance(refs, list) or not all(self.valid_id(x) for x in refs):
                self.add("error", "M-E3-ENV.ARTIFACTS", "artifact_refs must be an id array", loc)
                continue
            for ref in refs:
                if ref not in artifacts:
                    self.add("error", "M-E3-ENV.DANGLING", f"unresolved environment artifact: {ref}", loc)

    def check_policies(
        self,
        policies: dict[str, dict[str, Any]],
        artifacts: dict[str, dict[str, Any]],
    ) -> None:
        for pid, policy in policies.items():
            loc = f"{self.registry_path}#/equivalence_policies/{pid}"
            authority = policy.get("authority")
            if not isinstance(authority, str) or authority not in self.authorities:
                self.add("error", "M-E3-POLICY.AUTHORITY", f"unresolved authority: {authority}", loc)
            kind = policy.get("kind")
            if kind not in {"byte-exact", "canonical-equivalent", "semantic-equivalent"}:
                self.add("error", "M-E3-POLICY.KIND", f"invalid equivalence kind: {kind}", loc)
            refs = policy.get("comparator_artifacts", [])
            if not isinstance(refs, list):
                self.add("error", "M-E3-POLICY.ARTIFACTS", "comparator_artifacts must be an array", loc)
                continue
            for ref in refs:
                if ref not in artifacts:
                    self.add("error", "M-E3-POLICY.DANGLING", f"unresolved comparator artifact: {ref}", loc)

    def check_procedures(
        self,
        procedures: dict[str, dict[str, Any]],
        artifacts: dict[str, dict[str, Any]],
        policies: dict[str, dict[str, Any]],
    ) -> None:
        for pid, proc in procedures.items():
            loc = f"{self.registry_path}#/procedures/{pid}"
            authority = proc.get("authority")
            if not isinstance(authority, str) or authority not in self.authorities:
                self.add("error", "M-E3-PROCEDURE.AUTHORITY", f"unresolved authority: {authority}", loc)
            if proc.get("determinism") not in DETERMINISM:
                self.add("error", "M-E3-PROCEDURE.DETERMINISM", f"invalid determinism: {proc.get('determinism')}", loc)
            refs = proc.get("implementation_artifacts")
            if not isinstance(refs, list):
                self.add("error", "M-E3-PROCEDURE.ARTIFACTS", "implementation_artifacts must be an array", loc)
            else:
                for ref in refs:
                    if ref not in artifacts:
                        self.add("error", "M-E3-PROCEDURE.DANGLING", f"unresolved implementation artifact: {ref}", loc)
            ep = proc.get("equivalence_policy")
            if ep is not None and ep not in policies:
                self.add("error", "M-E3-PROCEDURE.POLICY", f"unresolved equivalence policy: {ep}", loc)

    @staticmethod
    def binding_map(bindings: Any) -> dict[str, str] | None:
        if not isinstance(bindings, list):
            return None
        result: dict[str, str] = {}
        for item in bindings:
            if not isinstance(item, dict):
                return None
            role = item.get("role")
            artifact = item.get("artifact")
            if not isinstance(role, str) or not role or not isinstance(artifact, str):
                return None
            if role in result:
                return None
            result[role] = artifact
        return result

    def check_events(
        self,
        events: dict[str, dict[str, Any]],
        artifacts: dict[str, dict[str, Any]],
        environments: dict[str, dict[str, Any]],
        procedures: dict[str, dict[str, Any]],
    ) -> dict[str, set[str]]:
        graph: dict[str, set[str]] = {aid: set() for aid in artifacts}
        for eid, event in events.items():
            loc = f"{self.registry_path}#/events/{eid}"
            if event.get("procedure") not in procedures:
                self.add("error", "M-E3-EVENT.PROCEDURE", f"unresolved procedure: {event.get('procedure')}", loc)
            if event.get("environment") not in environments:
                self.add("error", "M-E3-EVENT.ENVIRONMENT", f"unresolved environment: {event.get('environment')}", loc)
            if event.get("result") not in EVENT_RESULTS:
                self.add("error", "M-E3-EVENT.RESULT", f"invalid result: {event.get('result')}", loc)
            inputs = self.binding_map(event.get("inputs"))
            outputs = self.binding_map(event.get("outputs"))
            if inputs is None or outputs is None:
                self.add("error", "M-E3-EVENT.BINDINGS", "inputs and outputs must have unique non-empty roles", loc)
                continue
            for ref in list(inputs.values()) + list(outputs.values()):
                if ref not in artifacts:
                    self.add("error", "M-E3-EVENT.DANGLING", f"unresolved artifact: {ref}", loc)
            alias = set(inputs.values()) & set(outputs.values())
            for ref in sorted(alias):
                self.add("error", "M-E3-EVENT.ALIAS", f"immutable artifact used as both input and newly produced output: {ref}", loc)
            for src in inputs.values():
                for dst in outputs.values():
                    if src in artifacts and dst in artifacts:
                        graph[src].add(dst)
        return graph

    def check_cycles(self, graph: dict[str, set[str]]) -> None:
        WHITE, GRAY, BLACK = 0, 1, 2
        state = {node: WHITE for node in graph}

        def visit(node: str, stack: list[str]) -> None:
            state[node] = GRAY
            stack.append(node)
            for nxt in sorted(graph.get(node, ())):
                if state.get(nxt, WHITE) == WHITE:
                    visit(nxt, stack)
                elif state.get(nxt) == GRAY:
                    cycle = stack[stack.index(nxt):] + [nxt] if nxt in stack else [node, nxt]
                    self.add("error", "M-E3-CYCLE", "provenance cycle: " + " -> ".join(cycle), self.registry_path or "")
            stack.pop()
            state[node] = BLACK

        for node in sorted(graph):
            if state[node] == WHITE:
                visit(node, [])

    @staticmethod
    def identity_tuple(item: dict[str, Any]) -> tuple[int, str] | None:
        size = item.get("size")
        digests = item.get("digests")
        if not isinstance(size, int) or not isinstance(digests, dict):
            return None
        sha = digests.get("sha256")
        if not isinstance(sha, str) or not SHA256_RE.fullmatch(sha):
            return None
        return size, sha

    def check_replays(
        self,
        replays: dict[str, dict[str, Any]],
        events: dict[str, dict[str, Any]],
        artifacts: dict[str, dict[str, Any]],
        environments: dict[str, dict[str, Any]],
        procedures: dict[str, dict[str, Any]],
        policies: dict[str, dict[str, Any]],
    ) -> None:
        for rid, replay in replays.items():
            loc = f"{self.registry_path}#/replays/{rid}"
            target = events.get(replay.get("target_event"))
            if target is None:
                self.add("error", "M-E3-REPLAY.EVENT", f"unresolved target event: {replay.get('target_event')}", loc)
                continue
            if replay.get("procedure") not in procedures:
                self.add("error", "M-E3-REPLAY.PROCEDURE", f"unresolved procedure: {replay.get('procedure')}", loc)
            if replay.get("environment") not in environments:
                self.add("error", "M-E3-REPLAY.ENVIRONMENT", f"unresolved environment: {replay.get('environment')}", loc)
            relation = replay.get("relation")
            result = replay.get("result")
            if relation not in REPLAY_RELATIONS:
                self.add("error", "M-E3-REPLAY.RELATION", f"invalid relation: {relation}", loc)
            if result not in REPLAY_RESULTS:
                self.add("error", "M-E3-REPLAY.RESULT", f"invalid result: {result}", loc)
            if replay.get("independence") not in INDEPENDENCE:
                self.add("error", "M-E3-REPLAY.INDEPENDENCE", f"invalid independence: {replay.get('independence')}", loc)

            inputs = self.binding_map(replay.get("input_bindings"))
            observed = self.binding_map(replay.get("observed_outputs"))
            expected = self.binding_map(target.get("outputs"))
            if inputs is None or observed is None or expected is None:
                self.add("error", "M-E3-REPLAY.BINDINGS", "replay bindings must have unique non-empty roles", loc)
                continue
            for ref in list(inputs.values()) + list(observed.values()):
                if ref not in artifacts:
                    self.add("error", "M-E3-REPLAY.DANGLING", f"unresolved artifact: {ref}", loc)

            if relation in {"canonical-equivalent", "semantic-equivalent"}:
                ep = replay.get("equivalence_policy")
                if ep not in policies:
                    self.add("error", "M-E3-REPLAY.POLICY", "canonical/semantic replay requires resolved equivalence_policy", loc)

            if relation == "byte-exact" and result == "match":
                if set(expected) != set(observed):
                    self.add("error", "M-E3-REPLAY.ROLES", "byte-exact match requires exactly the expected output roles", loc)
                    continue
                for role in sorted(expected):
                    exp_id = expected[role]
                    obs_id = observed[role]
                    if exp_id == obs_id:
                        self.add("error", "M-E3-REPLAY.INSTANCE", f"replay output for role {role} reuses expected artifact instance instead of a distinct replay artifact", loc)
                        continue
                    exp = artifacts.get(exp_id)
                    obs = artifacts.get(obs_id)
                    if exp is None or obs is None:
                        continue
                    if self.identity_tuple(exp) is None or self.identity_tuple(obs) is None:
                        self.add("error", "M-E3-REPLAY.IDENTITY", f"byte-exact match lacks supported identity for role {role}", loc)
                        continue
                    if self.identity_tuple(exp) != self.identity_tuple(obs):
                        self.add("error", "M-E3-REPLAY.MISMATCH", f"declared byte-exact match differs for role {role}", loc)

    def load_e1_evidence_ids(self) -> set[str] | None:
        raw = self.config.get("registry")
        if not isinstance(raw, str):
            return None
        p = self.safe_path(raw)
        if p is None:
            return None
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        evidence = obj.get("evidence") if isinstance(obj, dict) else None
        if not isinstance(evidence, list):
            return None
        return {
            item.get("id")
            for item in evidence
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }

    def check_bindings(
        self,
        artifacts: dict[str, dict[str, Any]],
        events: dict[str, dict[str, Any]],
        replays: dict[str, dict[str, Any]],
    ) -> None:
        evidence_ids = self.load_e1_evidence_ids()
        seen: set[str] = set()
        for i, binding in enumerate(self.registry.get("evidence_bindings", [])):
            loc = f"{self.registry_path}#/evidence_bindings/{i}"
            if not isinstance(binding, dict):
                self.add("error", "M-E3-BINDING.TYPE", "evidence binding must be an object", loc)
                continue
            eid = binding.get("evidence_id")
            if not self.valid_id(eid):
                self.add("error", "M-E3-BINDING.ID", "invalid evidence_id", loc)
                continue
            if eid in seen:
                self.add("error", "M-E3-BINDING.DUPLICATE", f"duplicate evidence binding: {eid}", loc)
            seen.add(eid)
            if evidence_ids is not None and eid not in evidence_ids:
                self.add("error", "M-E3-BINDING.EVIDENCE", f"unresolved E1 evidence id: {eid}", loc)
            for key, index in (("artifacts", artifacts), ("production_events", events), ("replays", replays)):
                refs = binding.get(key, [])
                if not isinstance(refs, list):
                    self.add("error", "M-E3-BINDING.REFS", f"{key} must be an array", loc)
                    continue
                for ref in refs:
                    if ref not in index:
                        self.add("error", "M-E3-BINDING.DANGLING", f"unresolved {key} reference: {ref}", loc)

    def run(self) -> dict[str, Any]:
        if self.load_profile() and self.load_registry():
            artifacts = self.index_collection("artifacts")
            environments = self.index_collection("environments")
            policies = self.index_collection("equivalence_policies")
            procedures = self.index_collection("procedures")
            events = self.index_collection("events")
            replays = self.index_collection("replays")
            self.check_artifacts(artifacts)
            self.check_environments(environments, artifacts)
            self.check_policies(policies, artifacts)
            self.check_procedures(procedures, artifacts, policies)
            graph = self.check_events(events, artifacts, environments, procedures)
            self.check_cycles(graph)
            self.check_replays(replays, events, artifacts, environments, procedures, policies)
            self.check_bindings(artifacts, events, replays)

        findings = sorted(
            self.findings,
            key=lambda f: (f.severity, f.code, f.path, f.message),
        )
        errors = sum(f.severity == "error" for f in findings)
        return {
            "tool": "eigiib-provenance-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "revision": self.registry.get("revision", self.config.get("revision", "unknown")),
            "result": "non-conformant" if errors else "conformant",
            "findings": [asdict(f) for f in findings],
        }


def exit_code(report: dict[str, Any]) -> int:
    return 1 if report["result"] == "non-conformant" else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check EIGIIB-E3 provenance and local artifact identity without executing repository code."
    )
    parser.add_argument("root", nargs="?", default=".", help="repository root")
    parser.add_argument("--config", default="EIGIIB.toml", help="profile path relative to root")
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON report")
    args = parser.parse_args(argv)

    if sys.version_info < (3, 11):
        print("eigiib-provenance-check requires Python 3.11+", file=sys.stderr)
        return 3

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"repository root is not a directory: {root}", file=sys.stderr)
        return 64
    config = Path(args.config)
    if config.is_absolute() or ".." in config.parts:
        print("--config must be a repository-relative non-escaping path", file=sys.stderr)
        return 64

    report = Checker(root, config).run()
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(f"EIGIIB E3: {report['result']}")
        for finding in report["findings"]:
            where = f" [{finding['path']}]" if finding["path"] else ""
            print(f"{finding['severity'].upper():7} {finding['code']}{where}: {finding['message']}")
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
