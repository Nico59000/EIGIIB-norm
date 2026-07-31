#!/usr/bin/env python3
"""EIGIIB-E6 gossip, cross-log consistency, and fork-accountability checker.

Static by design: no network access, no repository command execution, no
cryptographic verification, and no Merkle recomputation. E4 and E5 remain
authoritative for their respective cryptographic and transparency semantics.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0"
MAX_ITEMS = 100_000


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Checker:
    def __init__(self, root: Path, registry_path: Path, transparency_path: Path, trust_path: Path):
        self.root = root.resolve()
        self.registry_path = registry_path
        self.transparency_path = transparency_path
        self.trust_path = trust_path
        self.findings: list[Finding] = []
        self.obj: dict[str, Any] = {}
        self.e5: dict[str, Any] = {}
        self.e4: dict[str, Any] = {}
        self.peers: dict[str, dict[str, Any]] = {}
        self.transmissions: dict[str, dict[str, Any]] = {}
        self.views: dict[str, dict[str, Any]] = {}
        self.comparison_policies: dict[str, dict[str, Any]] = {}
        self.comparisons: dict[str, dict[str, Any]] = {}
        self.forks: dict[str, dict[str, Any]] = {}
        self.cross_links: dict[str, dict[str, Any]] = {}
        self.cross_policies: dict[str, dict[str, Any]] = {}
        self.accountability_policies: dict[str, dict[str, Any]] = {}
        self.e5_entries: dict[str, dict[str, Any]] = {}
        self.e5_checkpoints: dict[str, dict[str, Any]] = {}
        self.e5_inclusion: dict[str, dict[str, Any]] = {}
        self.e5_consistency: dict[str, dict[str, Any]] = {}
        self.e4_decisions: dict[str, dict[str, Any]] = {}
        self.e4_attestations: dict[str, dict[str, Any]] = {}
        self.e4_policies: dict[str, dict[str, Any]] = {}
        self.e4_signatures: dict[str, dict[str, Any]] = {}
        self.e4_keys: dict[str, dict[str, Any]] = {}
        self.compared = 0
        self.anchored = 0
        self.accountability_evaluated = 0
        self.direct_conflict = False

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def safe_path(self, raw: str, *, must_exist: bool = True) -> Path | None:
        if not isinstance(raw, str) or not raw:
            self.add("error", "E6.PATH.INVALID", "path must be a non-empty string", str(raw))
            return None
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error", "E6.PATH.ESCAPE", "path escapes repository", raw)
            return None
        candidate = (self.root / p).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("error", "E6.PATH.ESCAPE", "resolved path escapes repository", raw)
            return None
        if must_exist:
            if not candidate.exists() or not candidate.is_file():
                self.add("error", "E6.PATH.MISSING", "file does not exist", raw)
                return None
            try:
                candidate.resolve(strict=True).relative_to(self.root)
            except (OSError, ValueError):
                self.add("error", "E6.PATH.SYMLINK", "unsafe resolved path", raw)
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

    @staticmethod
    def item_map(data: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        items = data.get(key, [])
        if not isinstance(items, list):
            return result
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                result[item["id"]] = item
        return result

    def map_e6(self, key: str, code: str) -> dict[str, dict[str, Any]]:
        items = self.obj.get(key)
        if not isinstance(items, list):
            self.add("error", "E6.COLLECTION", f"{key} must be an array", str(self.registry_path))
            return {}
        if len(items) > MAX_ITEMS:
            self.add("error", "E6.RESOURCE", f"{key} exceeds checker item limit", str(self.registry_path))
            return {}
        result: dict[str, dict[str, Any]] = {}
        for i, item in enumerate(items):
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

    def load(self) -> bool:
        obj = self.load_json(self.registry_path, "E6.REGISTRY")
        if obj is None:
            return False
        self.obj = obj
        if obj.get("standard") != STANDARD:
            self.add("error", "E6.STANDARD", "unsupported E6 standard identifier", str(self.registry_path))
        if not isinstance(obj.get("revision"), str) or not obj.get("revision"):
            self.add("error", "E6.REVISION", "revision must be a non-empty string", str(self.registry_path))
        required = [
            "peers", "transmissions", "views", "comparison_policies", "comparisons",
            "fork_evidence", "cross_log_links", "cross_log_policies",
            "cross_log_decisions", "accountability_policies", "accountability_decisions",
        ]
        for key in required:
            if not isinstance(obj.get(key), list):
                self.add("error", "E6.COLLECTION", f"{key} must be an array", str(self.registry_path))

        e5 = self.load_json(self.transparency_path, "E6.E5")
        e4 = self.load_json(self.trust_path, "E6.E4")
        if e5 is None or e4 is None:
            return True
        self.e5, self.e4 = e5, e4
        self.e5_entries = self.item_map(e5, "entries")
        self.e5_checkpoints = self.item_map(e5, "checkpoints")
        self.e5_inclusion = self.item_map(e5, "inclusion_proofs")
        self.e5_consistency = self.item_map(e5, "consistency_proofs")
        self.e4_decisions = self.item_map(e4, "decisions")
        self.e4_attestations = self.item_map(e4, "attestations")
        self.e4_policies = self.item_map(e4, "policies")
        self.e4_signatures = self.item_map(e4, "signatures")
        self.e4_keys = self.item_map(e4, "keys")
        return True

    @staticmethod
    def cp_identity(cp: dict[str, Any]) -> tuple[Any, Any, Any]:
        return cp.get("log"), cp.get("size"), cp.get("root_hash")

    def e5_entry_bytes(self, entry: dict[str, Any], loc: str) -> bytes | None:
        spec = entry.get("bytes")
        if not isinstance(spec, dict):
            self.add("error", "E6.E5.ENTRY_BYTES", "E5 entry bytes are unavailable", loc)
            return None
        path = spec.get("path")
        utf8 = spec.get("utf8")
        if isinstance(path, str) and utf8 is None:
            p = self.safe_path(path)
            if p is None:
                return None
            try:
                return p.read_bytes()
            except OSError as exc:
                self.add("error", "E6.E5.ENTRY_READ", f"cannot read E5 entry: {exc}", loc)
                return None
        if isinstance(utf8, str) and path is None:
            return utf8.encode("utf-8")
        self.add("error", "E6.E5.ENTRY_BYTES", "E5 entry bytes require exactly one representation", loc)
        return None

    def auth_binding(self, view: dict[str, Any]) -> tuple[bool, str | None]:
        decision_id = view.get("e4_decision")
        checkpoint_id = view.get("checkpoint")
        if not isinstance(decision_id, str) or not isinstance(checkpoint_id, str):
            return False, None
        decision = self.e4_decisions.get(decision_id)
        if decision is None or decision.get("state") != "authenticated":
            return False, None
        attestation = self.e4_attestations.get(decision.get("attestation"))
        if attestation is None:
            return False, None
        bindings = attestation.get("bindings", [])
        expected = f"e5-checkpoint:{checkpoint_id}"
        bound = any(
            isinstance(b, dict)
            and b.get("type") == "local"
            and b.get("id") == expected
            for b in bindings
        )
        if not bound:
            return False, None

        principal: str | None = None
        policy = self.e4_policies.get(decision.get("policy"))
        sigrefs = attestation.get("signatures", [])
        if (
            isinstance(policy, dict)
            and isinstance(policy.get("threshold"), dict)
            and policy["threshold"].get("count") == 1
            and isinstance(sigrefs, list)
            and len(sigrefs) == 1
        ):
            sig = self.e4_signatures.get(sigrefs[0])
            key = self.e4_keys.get(sig.get("key")) if isinstance(sig, dict) else None
            if isinstance(key, dict) and isinstance(key.get("principal"), str):
                principal = key["principal"]
        return True, principal

    def check_peers_views(self) -> None:
        self.peers = self.map_e6("peers", "E6.PEER")
        self.transmissions = self.map_e6("transmissions", "E6.TRANSMISSION")
        self.views = self.map_e6("views", "E6.VIEW")

        for tid, tr in self.transmissions.items():
            loc = f"transmission:{tid}"
            if tr.get("sender") not in self.peers or tr.get("receiver") not in self.peers:
                self.add("error", "E6.TRANSMISSION.PEER", "unresolved sender or receiver", loc)
            if tr.get("checkpoint") not in self.e5_checkpoints:
                self.add("error", "E6.TRANSMISSION.CHECKPOINT", "unresolved E5 checkpoint", loc)
            if tr.get("result") not in {"received", "dropped", "malformed", "unavailable", "not-applicable"}:
                self.add("error", "E6.TRANSMISSION.RESULT", "invalid transmission result", loc)

        for vid, view in self.views.items():
            loc = f"view:{vid}"
            if view.get("observer") not in self.peers:
                self.add("error", "E6.VIEW.OBSERVER", "unresolved observer", loc)
            if view.get("checkpoint") not in self.e5_checkpoints:
                self.add("error", "E6.VIEW.CHECKPOINT", "unresolved E5 checkpoint", loc)
            if view.get("source") == "gossip":
                tr = self.transmissions.get(view.get("transmission"))
                if tr is None:
                    self.add("error", "E6.VIEW.TRANSMISSION", "gossip view requires transmission", loc)
                elif tr.get("receiver") != view.get("observer") or tr.get("checkpoint") != view.get("checkpoint"):
                    self.add("error", "E6.VIEW.TRANSMISSION", "transmission does not bind observer/checkpoint", loc)

    def derived_comparison(self, cmp: dict[str, Any], policy: dict[str, Any]) -> str:
        lv = self.views.get(cmp.get("left_view"))
        rv = self.views.get(cmp.get("right_view"))
        if lv is None or rv is None:
            return "unresolved"
        lc = self.e5_checkpoints.get(lv.get("checkpoint"))
        rc = self.e5_checkpoints.get(rv.get("checkpoint"))
        if lc is None or rc is None:
            return "unresolved"
        li, ri = self.cp_identity(lc), self.cp_identity(rc)
        if li == ri:
            return "same-view"
        if li[0] == ri[0] and li[1] == ri[1] and li[2] != ri[2]:
            return "direct-conflict"
        if li[0] == ri[0] and isinstance(li[1], int) and isinstance(ri[1], int) and li[1] != ri[1]:
            if not policy.get("allow_e5_consistency_reference"):
                return "unresolved"
            ref = cmp.get("e5_consistency_proof")
            proof = self.e5_consistency.get(ref)
            if proof is None:
                return "unresolved"
            older_id = lv.get("checkpoint") if li[1] < ri[1] else rv.get("checkpoint")
            newer_id = rv.get("checkpoint") if li[1] < ri[1] else lv.get("checkpoint")
            if proof.get("older_checkpoint") == older_id and proof.get("newer_checkpoint") == newer_id:
                return "compatible-by-e5-reference"
        return "unresolved"

    def check_comparisons(self) -> None:
        self.comparison_policies = self.map_e6("comparison_policies", "E6.COMPARISON_POLICY")
        self.comparisons = self.map_e6("comparisons", "E6.COMPARISON")
        for cid, cmp in self.comparisons.items():
            loc = f"comparison:{cid}"
            policy = self.comparison_policies.get(cmp.get("policy"))
            if policy is None:
                self.add("error", "E6.COMPARISON.POLICY", "unresolved comparison policy", loc)
                continue
            if cmp.get("left_view") not in self.views or cmp.get("right_view") not in self.views:
                self.add("error", "E6.COMPARISON.VIEW", "unresolved comparison view", loc)
                continue
            derived = self.derived_comparison(cmp, policy)
            if cmp.get("state") != derived:
                self.add("error", "E6.COMPARISON.STATE", f"declared state {cmp.get('state')} != derived {derived}", loc)
                continue
            if policy.get("require_authenticated_views") and derived != "unresolved":
                lv, rv = self.views[cmp["left_view"]], self.views[cmp["right_view"]]
                if not self.auth_binding(lv)[0] or not self.auth_binding(rv)[0]:
                    self.add("error", "E6.COMPARISON.AUTH", "policy requires E4-authenticated checkpoint views", loc)
                    continue
            self.compared += 1
            if derived == "direct-conflict":
                self.direct_conflict = True

    def check_forks(self) -> None:
        self.forks = self.map_e6("fork_evidence", "E6.FORK")
        for fid, fork in self.forks.items():
            loc = f"fork:{fid}"
            cmp = self.comparisons.get(fork.get("comparison"))
            if cmp is None or cmp.get("state") != "direct-conflict" or fork.get("relation") != "direct-conflict":
                self.add("error", "E6.FORK.RELATION", "fork evidence requires direct-conflict comparison", loc)
                continue
            refs = fork.get("views")
            expected = {cmp.get("left_view"), cmp.get("right_view")}
            if not isinstance(refs, list) or not expected.issubset(set(refs)):
                self.add("error", "E6.FORK.VIEWS", "fork evidence must preserve both conflicting views", loc)
                continue
            if fork.get("state") == "authenticated-conflict":
                lv, rv = self.views.get(cmp.get("left_view")), self.views.get(cmp.get("right_view"))
                if lv is None or rv is None or not self.auth_binding(lv)[0] or not self.auth_binding(rv)[0]:
                    self.add("error", "E6.FORK.AUTH", "authenticated-conflict lacks E4-bound views", loc)

    def canonical_target(self, checkpoint_id: str) -> bytes | None:
        cp = self.e5_checkpoints.get(checkpoint_id)
        if cp is None:
            return None
        log_id, size, root = self.cp_identity(cp)
        if not isinstance(log_id, str) or not isinstance(size, int) or not isinstance(root, str):
            return None
        return f"eigiib-e6-cross-log-v1:{log_id}:{size}:{root}\n".encode("utf-8")

    def check_cross_log(self) -> None:
        self.cross_links = self.map_e6("cross_log_links", "E6.CROSS_LINK")
        self.cross_policies = self.map_e6("cross_log_policies", "E6.CROSS_POLICY")
        decisions = self.map_e6("cross_log_decisions", "E6.CROSS_DECISION")
        graph: dict[str, set[str]] = {}

        for lid, link in self.cross_links.items():
            loc = f"cross-link:{lid}"
            src = self.e5_checkpoints.get(link.get("source_checkpoint"))
            tgt = self.e5_checkpoints.get(link.get("target_checkpoint"))
            entry = self.e5_entries.get(link.get("source_entry"))
            proof = self.e5_inclusion.get(link.get("inclusion_proof"))
            if src is None or tgt is None or entry is None or proof is None:
                self.add("error", "E6.CROSS_LINK.REF", "unresolved E5 checkpoint/entry/proof", loc)
                continue
            if src.get("log") == tgt.get("log"):
                self.add("error", "E6.CROSS_LINK.SAME_LOG", "cross-log link must connect different logs", loc)
            if entry.get("log") != src.get("log"):
                self.add("error", "E6.CROSS_LINK.ENTRY", "source entry is not in source log", loc)
            if proof.get("entry") != link.get("source_entry") or proof.get("checkpoint") != link.get("source_checkpoint"):
                self.add("error", "E6.CROSS_LINK.PROOF", "E5 inclusion proof does not bind source entry/checkpoint", loc)
            data = self.e5_entry_bytes(entry, loc)
            expected = self.canonical_target(str(link.get("target_checkpoint")))
            if data is None or expected is None or data != expected:
                self.add("error", "E6.CROSS_LINK.BYTES", "source entry does not exactly encode target checkpoint identity", loc)
            graph.setdefault(str(link.get("source_checkpoint")), set()).add(str(link.get("target_checkpoint")))

        visiting: set[str] = set()
        done: set[str] = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in done:
                return False
            visiting.add(node)
            for nxt in graph.get(node, set()):
                if visit(nxt):
                    return True
            visiting.remove(node)
            done.add(node)
            return False

        for node in list(graph):
            if visit(node):
                self.add("error", "E6.CROSS_LINK.CYCLE", "exact cross-log anchor graph contains a cycle", node)
                break

        for did, dec in decisions.items():
            loc = f"cross-decision:{did}"
            policy = self.cross_policies.get(dec.get("policy"))
            if policy is None:
                self.add("error", "E6.CROSS_DECISION.POLICY", "unresolved cross-log policy", loc)
                continue
            refs = dec.get("links")
            if not isinstance(refs, list):
                self.add("error", "E6.CROSS_DECISION.LINKS", "links must be an array", loc)
                continue
            selected = [self.cross_links.get(x) for x in refs]
            if any(x is None for x in selected):
                self.add("error", "E6.CROSS_DECISION.LINKS", "unresolved cross-log link", loc)
                continue
            valid = True
            if len(set(refs)) < policy.get("minimum_anchors", 1):
                valid = False
            logs: set[str] = set()
            pairs: set[tuple[str, str]] = set()
            for link in selected:
                assert isinstance(link, dict)
                src = self.e5_checkpoints.get(link.get("source_checkpoint"), {})
                tgt = self.e5_checkpoints.get(link.get("target_checkpoint"), {})
                if isinstance(src.get("log"), str):
                    logs.add(src["log"])
                if isinstance(tgt.get("log"), str):
                    logs.add(tgt["log"])
                pairs.add((str(link.get("source_checkpoint")), str(link.get("target_checkpoint"))))
            required_logs = policy.get("required_logs", [])
            if not isinstance(required_logs, list) or any(x not in logs for x in required_logs):
                valid = False
            if policy.get("reciprocal") and any((b, a) not in pairs for a, b in pairs):
                valid = False
            if policy.get("require_authenticated_source_views"):
                for link in selected:
                    assert isinstance(link, dict)
                    source_cp = link.get("source_checkpoint")
                    candidates = [v for v in self.views.values() if v.get("checkpoint") == source_cp]
                    if not any(self.auth_binding(v)[0] for v in candidates):
                        valid = False
                        break
            expected = "anchored" if valid else "partially-anchored"
            if dec.get("state") != expected:
                self.add("error", "E6.CROSS_DECISION.STATE", f"declared {dec.get('state')} != derived {expected}", loc)
            elif valid:
                self.anchored += 1

    def derive_accountability(self, fork: dict[str, Any], policy: dict[str, Any]) -> tuple[str, str | None]:
        cmp = self.comparisons.get(fork.get("comparison"))
        if cmp is None or cmp.get("state") != "direct-conflict":
            return "insufficient-evidence", None
        sources = fork.get("evidence_sources", [])
        if not isinstance(sources, list) or len(set(sources)) < policy.get("minimum_evidence_sources", 1):
            return "insufficient-evidence", None
        lv = self.views.get(cmp.get("left_view"))
        rv = self.views.get(cmp.get("right_view"))
        if lv is None or rv is None:
            return "insufficient-evidence", None
        lauth, lp = self.auth_binding(lv)
        rauth, rp = self.auth_binding(rv)
        if policy.get("require_authenticated_views") and not (lauth and rauth):
            return "insufficient-evidence", None
        mode = policy.get("attribution_mode")
        if mode == "none":
            return "conflict-established", None
        if mode == "single-principal-v1":
            if lauth and rauth and lp is not None and lp == rp:
                return "single-principal-equivocation", lp
            if lauth and rauth:
                return "authenticated-conflict", None
            return "unattributed-conflict", None
        if mode == "manual":
            return ("authenticated-conflict" if lauth and rauth else "unattributed-conflict"), None
        return "insufficient-evidence", None

    def check_accountability(self) -> None:
        self.accountability_policies = self.map_e6("accountability_policies", "E6.ACCOUNTABILITY_POLICY")
        decisions = self.map_e6("accountability_decisions", "E6.ACCOUNTABILITY_DECISION")
        for did, dec in decisions.items():
            loc = f"accountability:{did}"
            policy = self.accountability_policies.get(dec.get("policy"))
            fork = self.forks.get(dec.get("fork_evidence"))
            if policy is None or fork is None:
                self.add("error", "E6.ACCOUNTABILITY.REF", "unresolved policy or fork evidence", loc)
                continue
            state, principal = self.derive_accountability(fork, policy)
            if dec.get("state") != state:
                self.add("error", "E6.ACCOUNTABILITY.STATE", f"declared {dec.get('state')} != derived {state}", loc)
                continue
            if state == "single-principal-equivocation":
                if dec.get("attributed_principal") != principal:
                    self.add("error", "E6.ACCOUNTABILITY.PRINCIPAL", "attributed principal does not match restricted E4 derivation", loc)
                    continue
            elif dec.get("attributed_principal") is not None:
                self.add("error", "E6.ACCOUNTABILITY.PRINCIPAL", "principal attribution is not permitted for this state", loc)
                continue
            self.accountability_evaluated += 1

    def run(self) -> dict[str, Any]:
        if self.load():
            self.check_peers_views()
            self.check_comparisons()
            self.check_forks()
            self.check_cross_log()
            self.check_accountability()
        findings = sorted(self.findings, key=lambda f: (f.severity, f.code, f.path, f.message))
        errors = sum(f.severity == "error" for f in findings)
        return {
            "tool": "eigiib-gossip-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "revision": self.obj.get("revision", "unknown"),
            "structural_result": "non-conformant" if errors else "conformant",
            "comparison_result": "compared" if self.compared else "not-evaluated",
            "cross_log_result": "anchored" if self.anchored else "not-evaluated",
            "accountability_result": (
                "attributed"
                if any(d.get("state") == "single-principal-equivocation" for d in self.obj.get("accountability_decisions", []) if isinstance(d, dict))
                and not errors
                else ("conflict-only" if self.accountability_evaluated else "not-evaluated")
            ),
            "fork_state": "direct-conflict-observed" if self.direct_conflict else "none-observed",
            "findings": [asdict(f) for f in findings],
        }


def exit_code(report: dict[str, Any]) -> int:
    return 1 if report["structural_result"] == "non-conformant" else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check EIGIIB-E6 gossip and fork-accountability records.")
    parser.add_argument("root", nargs="?", default=".", help="repository root")
    parser.add_argument("--registry", default="conformance/gossip.json", help="E6 registry relative to root")
    parser.add_argument("--transparency", default="conformance/transparency.json", help="E5 registry relative to root")
    parser.add_argument("--trust", default="conformance/trust.json", help="E4 registry relative to root")
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON")
    args = parser.parse_args(argv)

    if sys.version_info < (3, 11):
        print("eigiib-gossip-check requires Python 3.11+", file=sys.stderr)
        return 3
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"repository root is not a directory: {root}", file=sys.stderr)
        return 64
    for raw in (args.registry, args.transparency, args.trust):
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            print("registry paths must be repository-relative and non-escaping", file=sys.stderr)
            return 64

    checker = Checker(root, Path(args.registry), Path(args.transparency), Path(args.trust))
    report = checker.run()
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        for key in ("structural_result", "comparison_result", "cross_log_result", "accountability_result", "fork_state"):
            print(f"{key}: {report[key]}")
        for finding in report["findings"]:
            where = f" [{finding['path']}]" if finding["path"] else ""
            print(f"{finding['severity'].upper():7} {finding['code']}{where}: {finding['message']}")
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
