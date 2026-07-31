#!/usr/bin/env python3
"""EIGIIB-E5 transparency, witnessing, and append-only history checker.

Static by design: no network access, no repository command execution, and no
cryptographic authentication. E4 decisions may be consumed as already-derived
inputs, but E4 remains authoritative for authentication semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0"
TREE_PROFILE = "sha256-merkle-domain-v1"
CONSISTENCY_PROFILE = "prefix-recompute-v1"
MAX_ENTRIES = 100_000
MAX_PROOF_STEPS = 128
MAX_INLINE_BYTES = 1_000_000
MAX_CHECKPOINTS = 100_000
MAX_OBSERVATIONS = 100_000


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return h(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return h(b"\x01" + left + right)


def largest_power_two_less_than(n: int) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root_from_leaf_hashes(leaves: list[bytes]) -> bytes:
    if not leaves:
        return h(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = largest_power_two_less_than(len(leaves))
    return node_hash(
        merkle_root_from_leaf_hashes(leaves[:k]),
        merkle_root_from_leaf_hashes(leaves[k:]),
    )


def merkle_root(payloads: list[bytes]) -> bytes:
    return merkle_root_from_leaf_hashes([leaf_hash(x) for x in payloads])


class Checker:
    def __init__(self, root: Path, registry_path: Path, trust_path: Path | None):
        self.root = root.resolve()
        self.registry_path = registry_path
        self.trust_path = trust_path
        self.findings: list[Finding] = []
        self.obj: dict[str, Any] = {}
        self.logs: dict[str, dict[str, Any]] = {}
        self.entries: dict[str, dict[str, Any]] = {}
        self.checkpoints: dict[str, dict[str, Any]] = {}
        self.witnesses: dict[str, dict[str, Any]] = {}
        self.observations: dict[str, dict[str, Any]] = {}
        self.witness_policies: dict[str, dict[str, Any]] = {}
        self.authenticated_e4_decisions: set[str] = set()
        self.verified_consistency = 0
        self.verified_witness_decisions = 0
        self.verified_history_decisions = 0
        self.fork_observed = False

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def safe_path(self, raw: str, *, must_exist: bool = True) -> Path | None:
        if not isinstance(raw, str) or not raw:
            self.add("error", "E5.PATH.INVALID", "path must be non-empty", str(raw))
            return None
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error", "E5.PATH.ESCAPE", "path escapes repository", raw)
            return None
        candidate = (self.root / p).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("error", "E5.PATH.ESCAPE", "resolved path escapes repository", raw)
            return None
        if must_exist:
            if not candidate.exists() or not candidate.is_file():
                self.add("error", "E5.PATH.MISSING", "file does not exist", raw)
                return None
            try:
                candidate.resolve(strict=True).relative_to(self.root)
            except (OSError, ValueError):
                self.add("error", "E5.PATH.SYMLINK", "unsafe resolved path", raw)
                return None
        return candidate

    def load_json(self, rel: Path, code: str) -> dict[str, Any] | None:
        p = self.safe_path(str(rel))
        if p is None:
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.add("error", f"{code}.PARSE", f"cannot parse JSON: {exc}", str(rel))
            return None
        if not isinstance(data, dict):
            self.add("error", f"{code}.TYPE", "registry root must be an object", str(rel))
            return None
        return data

    def load(self) -> bool:
        data = self.load_json(self.registry_path, "E5.REGISTRY")
        if data is None:
            return False
        self.obj = data
        if data.get("standard") != STANDARD:
            self.add("error", "E5.STANDARD", "unsupported E5 standard identifier", str(self.registry_path))
        revision = data.get("revision")
        if not isinstance(revision, str) or not revision.strip():
            self.add("error", "E5.REVISION", "revision must be a non-empty string", str(self.registry_path))
        required_arrays = [
            "logs", "entries", "checkpoints", "inclusion_proofs", "consistency_proofs",
            "witnesses", "observations", "witness_policies", "witness_decisions",
            "trust_history_events", "trust_history_policies", "trust_history_decisions",
        ]
        for key in required_arrays:
            if not isinstance(data.get(key), list):
                self.add("error", "E5.COLLECTION", f"{key} must be an array", str(self.registry_path))
        if len(data.get("entries", [])) > MAX_ENTRIES:
            self.add("error", "E5.RESOURCE.ENTRIES", "entry count exceeds checker limit")
        if len(data.get("checkpoints", [])) > MAX_CHECKPOINTS:
            self.add("error", "E5.RESOURCE.CHECKPOINTS", "checkpoint count exceeds checker limit")
        if len(data.get("observations", [])) > MAX_OBSERVATIONS:
            self.add("error", "E5.RESOURCE.OBSERVATIONS", "observation count exceeds checker limit")
        self.load_e4_decisions()
        return True

    def load_e4_decisions(self) -> None:
        if self.trust_path is None:
            return
        p = (self.root / self.trust_path).resolve(strict=False)
        if not p.exists():
            return
        data = self.load_json(self.trust_path, "E5.E4")
        if data is None:
            return
        decisions = data.get("decisions", [])
        if not isinstance(decisions, list):
            return
        for item in decisions:
            if isinstance(item, dict) and item.get("state") == "authenticated" and isinstance(item.get("id"), str):
                self.authenticated_e4_decisions.add(item["id"])

    def map_items(self, key: str, code: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for i, item in enumerate(self.obj.get(key, [])):
            loc = f"{self.registry_path}#/{key}/{i}"
            if not isinstance(item, dict):
                self.add("error", f"{code}.TYPE", "item must be an object", loc)
                continue
            iid = item.get("id")
            if not isinstance(iid, str) or not iid:
                self.add("error", f"{code}.ID", "item requires non-empty id", loc)
                continue
            if iid in result:
                self.add("error", f"{code}.DUPLICATE", f"duplicate id: {iid}", loc)
            result[iid] = item
        return result

    def entry_bytes(self, entry: dict[str, Any], loc: str) -> bytes | None:
        spec = entry.get("bytes")
        if not isinstance(spec, dict):
            self.add("error", "E5.ENTRY.BYTES", "entry bytes must be an object", loc)
            return None
        has_path = "path" in spec
        has_utf8 = "utf8" in spec
        if has_path == has_utf8:
            self.add("error", "E5.ENTRY.BYTES", "entry bytes require exactly one of path or utf8", loc)
            return None
        if has_path:
            p = self.safe_path(spec.get("path"))
            if p is None:
                return None
            try:
                return p.read_bytes()
            except OSError as exc:
                self.add("error", "E5.ENTRY.READ", f"cannot read entry bytes: {exc}", loc)
                return None
        raw = spec.get("utf8")
        if not isinstance(raw, str):
            self.add("error", "E5.ENTRY.UTF8", "utf8 entry must be a string", loc)
            return None
        data = raw.encode("utf-8")
        if len(data) > MAX_INLINE_BYTES:
            self.add("error", "E5.RESOURCE.INLINE", "inline entry exceeds checker limit", loc)
            return None
        return data

    def check_logs_entries_checkpoints(self) -> None:
        self.logs = self.map_items("logs", "E5.LOG")
        self.entries = self.map_items("entries", "E5.ENTRY")
        self.checkpoints = self.map_items("checkpoints", "E5.CHECKPOINT")

        for lid, log in self.logs.items():
            if log.get("tree_profile") != TREE_PROFILE:
                self.add("error", "E5.LOG.PROFILE", f"unsupported tree profile for {lid}")

        index_seen: dict[tuple[str, int], str] = {}
        for eid, entry in self.entries.items():
            loc = f"entry:{eid}"
            log_id = entry.get("log")
            idx = entry.get("index")
            if log_id not in self.logs:
                self.add("error", "E5.ENTRY.LOG", f"unresolved log: {log_id}", loc)
            if not isinstance(idx, int) or idx < 0:
                self.add("error", "E5.ENTRY.INDEX", "index must be non-negative integer", loc)
                continue
            key = (str(log_id), idx)
            if key in index_seen:
                self.add("error", "E5.ENTRY.INDEX_CONFLICT", f"duplicate log/index with {index_seen[key]}", loc)
            index_seen[key] = eid
            self.entry_bytes(entry, loc)

        same_size: dict[tuple[str, int], tuple[str, str]] = {}
        for cid, cp in self.checkpoints.items():
            loc = f"checkpoint:{cid}"
            log_id = cp.get("log")
            size = cp.get("size")
            root = cp.get("root_hash")
            if log_id not in self.logs:
                self.add("error", "E5.CHECKPOINT.LOG", f"unresolved log: {log_id}", loc)
            if not isinstance(size, int) or size < 0:
                self.add("error", "E5.CHECKPOINT.SIZE", "size must be non-negative integer", loc)
                continue
            if not isinstance(root, str) or len(root) != 64:
                self.add("error", "E5.CHECKPOINT.ROOT", "root_hash must be lowercase SHA-256 hex", loc)
                continue
            try:
                bytes.fromhex(root)
            except ValueError:
                self.add("error", "E5.CHECKPOINT.ROOT", "root_hash is not valid hex", loc)
                continue
            key = (str(log_id), size)
            prior = same_size.get(key)
            if prior and prior[1] != root:
                self.fork_observed = True
                self.add("error", "E5.FORK.SAME_SIZE", f"same log/size has conflicting roots: {prior[0]} vs {cid}", loc)
            else:
                same_size[key] = (cid, root)

            seq = self.entries_for_log(str(log_id), size)
            if seq is not None:
                payloads: list[bytes] = []
                for e in seq:
                    b = self.entry_bytes(e, loc)
                    if b is None:
                        payloads = []
                        break
                    payloads.append(b)
                if len(payloads) == size:
                    calculated = merkle_root(payloads).hex()
                    if calculated != root:
                        self.add("error", "E5.CHECKPOINT.ROOT_MISMATCH", f"recomputed root differs for {cid}", loc)

    def entries_for_log(self, log_id: str, size: int) -> list[dict[str, Any]] | None:
        by_index: dict[int, dict[str, Any]] = {}
        for entry in self.entries.values():
            if entry.get("log") == log_id and isinstance(entry.get("index"), int):
                idx = entry["index"]
                if idx < size:
                    by_index[idx] = entry
        if len(by_index) != size or any(i not in by_index for i in range(size)):
            return None
        return [by_index[i] for i in range(size)]

    def check_inclusion(self) -> None:
        proofs = self.map_items("inclusion_proofs", "E5.INCLUSION")
        for pid, proof in proofs.items():
            loc = f"inclusion:{pid}"
            entry = self.entries.get(proof.get("entry"))
            cp = self.checkpoints.get(proof.get("checkpoint"))
            if entry is None or cp is None:
                self.add("error", "E5.INCLUSION.REF", "unresolved entry or checkpoint", loc)
                continue
            if entry.get("log") != cp.get("log"):
                self.add("error", "E5.INCLUSION.LOG", "entry/checkpoint log mismatch", loc)
                continue
            idx = entry.get("index")
            size = cp.get("size")
            if not isinstance(idx, int) or not isinstance(size, int) or idx >= size:
                self.add("error", "E5.INCLUSION.INDEX", "entry index not covered by checkpoint", loc)
                continue
            data = self.entry_bytes(entry, loc)
            if data is None:
                continue
            current = leaf_hash(data)
            path = proof.get("path")
            if not isinstance(path, list) or len(path) > MAX_PROOF_STEPS:
                self.add("error", "E5.INCLUSION.PATH", "invalid or oversized proof path", loc)
                continue
            valid = True
            for step in path:
                if not isinstance(step, dict) or step.get("side") not in {"left", "right"}:
                    valid = False
                    break
                raw = step.get("hash")
                if not isinstance(raw, str) or len(raw) != 64:
                    valid = False
                    break
                try:
                    sibling = bytes.fromhex(raw)
                except ValueError:
                    valid = False
                    break
                current = node_hash(sibling, current) if step["side"] == "left" else node_hash(current, sibling)
            if not valid:
                self.add("error", "E5.INCLUSION.PATH", "malformed inclusion path", loc)
                continue
            if current.hex() != cp.get("root_hash"):
                self.add("error", "E5.INCLUSION.INVALID", "inclusion path does not yield checkpoint root", loc)

    def check_consistency(self) -> None:
        proofs = self.map_items("consistency_proofs", "E5.CONSISTENCY")
        for pid, proof in proofs.items():
            loc = f"consistency:{pid}"
            if proof.get("profile") != CONSISTENCY_PROFILE:
                self.add("warning", "E5.CONSISTENCY.UNSUPPORTED", "unsupported consistency profile", loc)
                continue
            old = self.checkpoints.get(proof.get("older_checkpoint"))
            new = self.checkpoints.get(proof.get("newer_checkpoint"))
            if old is None or new is None:
                self.add("error", "E5.CONSISTENCY.REF", "unresolved checkpoint", loc)
                continue
            if old.get("log") != new.get("log"):
                self.add("error", "E5.CONSISTENCY.LOG", "checkpoint log mismatch", loc)
                continue
            osize, nsize = old.get("size"), new.get("size")
            if not isinstance(osize, int) or not isinstance(nsize, int) or osize > nsize:
                self.add("error", "E5.CONSISTENCY.SIZE", "older size must be <= newer size", loc)
                continue
            refs = proof.get("entries")
            if not isinstance(refs, list) or len(refs) != nsize:
                self.add("error", "E5.CONSISTENCY.ENTRIES", "proof must contain exactly newer size entries", loc)
                continue
            seq: list[dict[str, Any]] = []
            ok = True
            for i, ref in enumerate(refs):
                entry = self.entries.get(ref)
                if entry is None or entry.get("log") != new.get("log") or entry.get("index") != i:
                    ok = False
                    break
                seq.append(entry)
            if not ok:
                self.add("error", "E5.CONSISTENCY.SEQUENCE", "entries are not exact contiguous log prefix", loc)
                continue
            payloads: list[bytes] = []
            for entry in seq:
                data = self.entry_bytes(entry, loc)
                if data is None:
                    ok = False
                    break
                payloads.append(data)
            if not ok:
                continue
            old_root = merkle_root(payloads[:osize]).hex()
            new_root = merkle_root(payloads).hex()
            if old_root != old.get("root_hash") or new_root != new.get("root_hash"):
                self.add("error", "E5.CONSISTENCY.INVALID", "prefix recomputation does not match checkpoints", loc)
                continue
            self.verified_consistency += 1

    def check_witnessing(self) -> None:
        self.witnesses = self.map_items("witnesses", "E5.WITNESS")
        self.observations = self.map_items("observations", "E5.OBSERVATION")
        self.witness_policies = self.map_items("witness_policies", "E5.WITNESS_POLICY")
        decisions = self.map_items("witness_decisions", "E5.WITNESS_DECISION")

        for oid, obs in self.observations.items():
            if obs.get("witness") not in self.witnesses:
                self.add("error", "E5.OBSERVATION.WITNESS", f"unresolved witness: {obs.get('witness')}", f"observation:{oid}")
            if obs.get("checkpoint") not in self.checkpoints:
                self.add("error", "E5.OBSERVATION.CHECKPOINT", f"unresolved checkpoint: {obs.get('checkpoint')}", f"observation:{oid}")

        for did, decision in decisions.items():
            loc = f"witness-decision:{did}"
            if decision.get("state") != "witnessed":
                continue
            cp = self.checkpoints.get(decision.get("checkpoint"))
            policy = self.witness_policies.get(decision.get("policy"))
            if cp is None or policy is None:
                self.add("error", "E5.WITNESS_DECISION.REF", "unresolved checkpoint or policy", loc)
                continue
            if policy.get("log") != cp.get("log"):
                self.add("error", "E5.WITNESS_DECISION.LOG", "policy/checkpoint log mismatch", loc)
                continue
            refs = decision.get("observations")
            if not isinstance(refs, list):
                self.add("error", "E5.WITNESS_DECISION.OBS", "observations must be an array", loc)
                continue
            selected: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for ref in refs:
                obs = self.observations.get(ref)
                if obs is None or obs.get("checkpoint") != decision.get("checkpoint") or obs.get("result") != "observed":
                    self.add("error", "E5.WITNESS_DECISION.OBS", f"invalid observation for witnessed decision: {ref}", loc)
                    continue
                witness = self.witnesses.get(obs.get("witness"))
                if witness is None:
                    continue
                if policy.get("require_authenticated"):
                    e4id = obs.get("e4_decision")
                    if e4id not in self.authenticated_e4_decisions:
                        self.add("error", "E5.WITNESS_DECISION.AUTH", f"observation lacks authenticated E4 decision: {ref}", loc)
                        continue
                selected.append((obs, witness))
            distinct_by = policy.get("distinct_by")
            if distinct_by not in {"witness", "principal", "domain"}:
                self.add("error", "E5.WITNESS_POLICY.DISTINCT", "unsupported distinct_by", loc)
                continue
            vals: set[str] = set()
            for obs, witness in selected:
                if distinct_by == "witness":
                    val = str(obs.get("witness"))
                else:
                    val = witness.get(distinct_by)
                    if not isinstance(val, str) or not val:
                        self.add("error", "E5.WITNESS_DECISION.DISTINCT", f"missing {distinct_by} for witness", loc)
                        continue
                vals.add(val)
            minimum = policy.get("minimum")
            if not isinstance(minimum, int) or minimum < 0:
                self.add("error", "E5.WITNESS_POLICY.MINIMUM", "minimum must be non-negative integer", loc)
                continue
            if len(vals) < minimum:
                self.add("error", "E5.WITNESS_DECISION.QUORUM", f"witness distinctness quorum not met: {len(vals)} < {minimum}", loc)
            required_domains = policy.get("required_domains", [])
            domains = {w.get("domain") for _, w in selected if isinstance(w.get("domain"), str)}
            if not isinstance(required_domains, list) or any(d not in domains for d in required_domains):
                self.add("error", "E5.WITNESS_DECISION.DOMAINS", "required witness domains not satisfied", loc)
            if not any(f.path == loc and f.severity == "error" for f in self.findings):
                self.verified_witness_decisions += 1

    def check_trust_history(self) -> None:
        events = self.map_items("trust_history_events", "E5.HISTORY_EVENT")
        policies = self.map_items("trust_history_policies", "E5.HISTORY_POLICY")
        decisions = self.map_items("trust_history_decisions", "E5.HISTORY_DECISION")

        for hid, event in events.items():
            if event.get("entry") not in self.entries:
                self.add("error", "E5.HISTORY_EVENT.ENTRY", f"unresolved entry: {event.get('entry')}", f"history-event:{hid}")
            if not isinstance(event.get("e4_object"), str) or not event.get("e4_object"):
                self.add("error", "E5.HISTORY_EVENT.E4", "history event requires e4_object id", f"history-event:{hid}")

        for did, decision in decisions.items():
            loc = f"history-decision:{did}"
            if decision.get("state") != "bound":
                continue
            policy = policies.get(decision.get("policy"))
            if policy is None:
                self.add("error", "E5.HISTORY_DECISION.POLICY", "unresolved history policy", loc)
                continue
            refs = decision.get("events")
            if not isinstance(refs, list):
                self.add("error", "E5.HISTORY_DECISION.EVENTS", "events must be an array", loc)
                continue
            selected = [events.get(ref) for ref in refs]
            if any(x is None for x in selected):
                self.add("error", "E5.HISTORY_DECISION.EVENTS", "unresolved history event", loc)
                continue
            required_classes = policy.get("required_classes", [])
            classes = {e.get("event_class") for e in selected if isinstance(e, dict)}
            if not isinstance(required_classes, list) or any(c not in classes for c in required_classes):
                self.add("error", "E5.HISTORY_DECISION.COVERAGE", "required history classes not represented", loc)
            if policy.get("require_e4_authenticated"):
                for event in selected:
                    e4id = event.get("e4_attestation") if isinstance(event, dict) else None
                    if e4id not in self.authenticated_e4_decisions:
                        self.add("error", "E5.HISTORY_DECISION.AUTH", "history event lacks authenticated E4 decision", loc)
                        break
            if not any(f.path == loc and f.severity == "error" for f in self.findings):
                self.verified_history_decisions += 1

    def run(self) -> dict[str, Any]:
        if self.load():
            self.check_logs_entries_checkpoints()
            self.check_inclusion()
            self.check_consistency()
            self.check_witnessing()
            self.check_trust_history()
        findings = sorted(self.findings, key=lambda x: (x.severity, x.code, x.path, x.message))
        errors = sum(f.severity == "error" for f in findings)
        structural = "non-conformant" if errors else "conformant"
        append_only = "verified" if self.verified_consistency else "not-evaluated"
        witness = "witnessed" if self.verified_witness_decisions else "not-evaluated"
        history = "bound" if self.verified_history_decisions else "not-evaluated"
        return {
            "tool": "eigiib-transparency-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "revision": self.obj.get("revision", "unknown"),
            "structural_result": structural,
            "append_only_result": append_only,
            "witness_result": witness,
            "trust_history_result": history,
            "fork_state": "observed" if self.fork_observed else "none-observed",
            "findings": [asdict(x) for x in findings],
        }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check EIGIIB-E5 transparency registry")
    p.add_argument("root", nargs="?", default=".")
    p.add_argument("--registry", default="conformance/transparency.json")
    p.add_argument("--trust-registry", default="conformance/trust.json")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"repository root is not a directory: {root}")
        return 64
    for raw in (args.registry, args.trust_registry):
        pp = Path(raw)
        if pp.is_absolute() or ".." in pp.parts:
            print("registry paths must be repository-relative and non-escaping")
            return 64
    checker = Checker(root, Path(args.registry), Path(args.trust_registry))
    report = checker.run()
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(f"structural:    {report['structural_result']}")
        print(f"append-only:   {report['append_only_result']}")
        print(f"witness:       {report['witness_result']}")
        print(f"trust-history: {report['trust_history_result']}")
        print(f"fork-state:    {report['fork_state']}")
        for finding in report["findings"]:
            where = f" [{finding['path']}]" if finding["path"] else ""
            print(f"{finding['severity'].upper():7} {finding['code']}{where}: {finding['message']}")
    return 1 if report["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
