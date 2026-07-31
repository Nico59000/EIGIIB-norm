#!/usr/bin/env python3
"""Static EIGIIB-E4 trust/attestation checker.

No repository-provided command is executed. Optional cryptographic verification
uses a fixed OpenSSL argv for the explicitly supported Ed25519 suite.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E4-1.0"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
SUITE = "ed25519-openssl-raw-v1"
DECISION_STATES = {
    "authenticated", "cryptographically-valid-untrusted", "policy-unsatisfied",
    "revoked", "expired", "not-yet-valid", "invalid-signature",
    "partially-evaluated", "unavailable", "not-applicable",
}

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

class Checker:
    def __init__(self, root: Path, registry: Path, crypto_provider: str):
        self.root = root.resolve()
        self.registry_path = registry
        self.crypto_provider = crypto_provider
        self.findings: list[Finding] = []
        self.obj: dict[str, Any] = {}
        self.maps: dict[str, dict[str, dict[str, Any]]] = {}
        self.crypto_attempted = 0
        self.crypto_valid = 0
        self.crypto_invalid = 0
        self.crypto_unavailable = 0

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def safe_path(self, raw: str, *, must_exist: bool = True) -> Path | None:
        if not isinstance(raw, str) or not raw:
            self.add("error", "E4-PATH.INVALID", "path must be non-empty string", str(raw))
            return None
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error", "E4-PATH.ESCAPE", "path escapes repository", raw)
            return None
        candidate = (self.root / p).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("error", "E4-PATH.ESCAPE", "resolved path escapes repository", raw)
            return None
        if must_exist and not candidate.is_file():
            self.add("error", "E4-PATH.MISSING", "file does not exist", raw)
            return None
        return candidate

    def load(self) -> bool:
        p = self.safe_path(str(self.registry_path))
        if p is None:
            return False
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.add("error", "E4-REGISTRY.PARSE", f"cannot parse registry: {exc}", str(self.registry_path))
            return False
        if not isinstance(obj, dict):
            self.add("error", "E4-REGISTRY.TYPE", "registry root must be object", str(self.registry_path))
            return False
        self.obj = obj
        if obj.get("standard") != STANDARD:
            self.add("error", "E4-REGISTRY.STANDARD", f"standard must be {STANDARD}", str(self.registry_path))
        if not isinstance(obj.get("revision"), str) or not obj.get("revision"):
            self.add("error", "E4-REGISTRY.REVISION", "revision must be non-empty", str(self.registry_path))
        for name in ("principals", "keys", "roots", "policies", "delegations", "revocations", "attestations", "signatures", "decisions"):
            items = obj.get(name)
            if not isinstance(items, list):
                self.add("error", "E4-REGISTRY.COLLECTION", f"{name} must be an array", str(self.registry_path))
                self.maps[name] = {}
                continue
            m: dict[str, dict[str, Any]] = {}
            for i, item in enumerate(items):
                loc = f"{self.registry_path}#/{name}/{i}"
                if not isinstance(item, dict):
                    self.add("error", "E4-REGISTRY.ITEM", f"{name} item must be object", loc)
                    continue
                rid = item.get("id")
                if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
                    self.add("error", "E4-REGISTRY.ID", f"invalid {name} id", loc)
                    continue
                if rid in m:
                    self.add("error", "E4-REGISTRY.DUPLICATE", f"duplicate {name} id: {rid}", loc)
                m[rid] = item
            self.maps[name] = m
        return True

    def check_refs(self) -> None:
        principals, keys, roots = self.maps["principals"], self.maps["keys"], self.maps["roots"]
        policies = self.maps["policies"]
        attestations, signatures = self.maps["attestations"], self.maps["signatures"]
        for kid, key in keys.items():
            if key.get("principal") not in principals:
                self.add("error", "E4-KEY.PRINCIPAL", f"unresolved principal: {key.get('principal')}", kid)
            if key.get("suite") != SUITE:
                self.add("warning", "E4-KEY.SUITE", f"reference checker does not support suite: {key.get('suite')}", kid)
            pub = self.safe_path(key.get("public_key", ""))
            fp = key.get("fingerprint")
            if pub is not None and isinstance(fp, dict):
                if fp.get("algorithm") != "sha256" or not isinstance(fp.get("digest"), str):
                    self.add("error", "E4-KEY.FINGERPRINT", "fingerprint must be sha256", kid)
                else:
                    actual = hashlib.sha256(pub.read_bytes()).hexdigest()
                    if actual != fp.get("digest"):
                        self.add("error", "E4-KEY.FINGERPRINT", "public-key fingerprint mismatch", kid)
        for rid, root in roots.items():
            key = keys.get(root.get("key"))
            if key is None:
                self.add("error", "E4-ROOT.KEY", f"unresolved root key: {root.get('key')}", rid)
            if root.get("principal") not in principals:
                self.add("error", "E4-ROOT.PRINCIPAL", f"unresolved root principal: {root.get('principal')}", rid)
            if key is not None and root.get("principal") != key.get("principal"):
                self.add("error", "E4-ROOT.BINDING", "root principal differs from key principal", rid)
        for pid, pol in policies.items():
            for rid in pol.get("roots", []):
                if rid not in roots:
                    self.add("error", "E4-POLICY.ROOT", f"unresolved root: {rid}", pid)
            if not isinstance(pol.get("allowed_suites"), list) or not pol.get("allowed_suites"):
                self.add("error", "E4-POLICY.SUITES", "allowed_suites must be non-empty", pid)
        for sid, sig in signatures.items():
            if sig.get("attestation") not in attestations:
                self.add("error", "E4-SIG.ATTESTATION", f"unresolved attestation: {sig.get('attestation')}", sid)
            if sig.get("key") not in keys:
                self.add("error", "E4-SIG.KEY", f"unresolved key: {sig.get('key')}", sid)
            self.safe_path(sig.get("signature", ""))
        for aid, att in attestations.items():
            self.safe_path(att.get("statement", ""))
            for sid in att.get("signatures", []):
                sig = signatures.get(sid)
                if sig is None:
                    self.add("error", "E4-ATT.SIGNATURE", f"unresolved signature: {sid}", aid)
                elif sig.get("attestation") != aid:
                    self.add("error", "E4-ATT.SIGNATURE", f"signature {sid} binds another attestation", aid)

    def check_delegation_graph(self) -> None:
        keys = self.maps["keys"]
        graph: dict[str, list[str]] = {k: [] for k in keys}
        for did, d in self.maps["delegations"].items():
            a, b = d.get("from_key"), d.get("to_key")
            if a not in keys or b not in keys:
                self.add("error", "E4-DELEGATION.KEY", "delegation key reference unresolved", did)
                continue
            graph[a].append(b)
            if d.get("attestation") not in self.maps["attestations"]:
                self.add("error", "E4-DELEGATION.ATTESTATION", "delegation attestation unresolved", did)
        visiting: set[str] = set()
        done: set[str] = set()
        def dfs(node: str) -> None:
            if node in done:
                return
            if node in visiting:
                self.add("error", "E4-DELEGATION.CYCLE", f"delegation cycle reaches key {node}")
                return
            visiting.add(node)
            for nxt in graph.get(node, []):
                dfs(nxt)
            visiting.remove(node)
            done.add(node)
        for node in sorted(graph):
            dfs(node)

    def verify_signature(self, att: dict[str, Any], sig: dict[str, Any]) -> str:
        if sig.get("suite") != SUITE:
            return "unsupported-suite"
        key = self.maps["keys"].get(sig.get("key"))
        if key is None:
            return "unavailable"
        statement = self.safe_path(att.get("statement", ""))
        public_key = self.safe_path(key.get("public_key", ""))
        signature = self.safe_path(sig.get("signature", ""))
        if None in (statement, public_key, signature):
            return "unavailable"
        if self.crypto_provider == "none":
            return "unverified"
        encoding = sig.get("signature_encoding", "raw")
        if encoding not in {"raw", "base64"}:
            return "unavailable"
        openssl = shutil.which("openssl")
        if openssl is None:
            self.crypto_unavailable += 1
            return "unavailable"
        self.crypto_attempted += 1
        temp_sig = None
        sig_arg = signature
        try:
            if encoding == "base64":
                try:
                    raw_sig = base64.b64decode(signature.read_text(encoding="ascii"), validate=True)
                except (OSError, UnicodeError, ValueError):
                    self.crypto_unavailable += 1
                    return "unavailable"
                temp_sig = tempfile.NamedTemporaryFile(prefix="eigiib-e4-sig-", delete=False)
                temp_sig.write(raw_sig)
                temp_sig.close()
                sig_arg = Path(temp_sig.name)
            cp = subprocess.run(
                [openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key), "-in", str(statement), "-sigfile", str(sig_arg)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            self.crypto_unavailable += 1
            return "unavailable"
        finally:
            if temp_sig is not None:
                try:
                    Path(temp_sig.name).unlink()
                except OSError:
                    pass
        if cp.returncode == 0:
            self.crypto_valid += 1
            return "valid"
        self.crypto_invalid += 1
        return "invalid"

    def direct_root_auth(self, att: dict[str, Any], policy: dict[str, Any]) -> tuple[str, list[str]]:
        roots = self.maps["roots"]
        keys = self.maps["keys"]
        sigs = self.maps["signatures"]
        allowed_roots = [roots[r] for r in policy.get("roots", []) if r in roots]
        purpose = policy.get("purpose")
        valid_signers: list[tuple[str, str]] = []
        any_crypto_valid = False
        any_invalid = False
        any_unavailable = False
        for sid in att.get("signatures", []):
            sig = sigs.get(sid)
            if sig is None:
                continue
            state = self.verify_signature(att, sig)
            if state == "valid":
                any_crypto_valid = True
            elif state == "invalid":
                any_invalid = True
                continue
            elif state in {"unverified", "unavailable", "unsupported-suite"}:
                any_unavailable = True
                continue
            key = keys.get(sig.get("key"))
            if key is None:
                continue
            if sig.get("suite") not in policy.get("allowed_suites", []):
                continue
            for root in allowed_roots:
                if root.get("key") != sig.get("key"):
                    continue
                if purpose not in root.get("purposes", []):
                    continue
                if policy.get("environment") == "production" and key.get("test_only"):
                    continue
                valid_signers.append((sig.get("key"), key.get("principal")))
                break
        threshold = policy.get("threshold", {})
        count = threshold.get("count", 1)
        distinct_by = threshold.get("distinct_by", "key")
        values = {k if distinct_by == "key" else p for k, p in valid_signers}
        if len(values) >= count:
            return "authenticated", sorted(values)
        if any_invalid and not any_crypto_valid:
            return "invalid-signature", []
        if any_crypto_valid:
            return "cryptographically-valid-untrusted", []
        if any_unavailable:
            return "unavailable", []
        return "policy-unsatisfied", []

    def check_decisions(self) -> None:
        policies = self.maps["policies"]
        atts = self.maps["attestations"]
        for did, dec in self.maps["decisions"].items():
            declared = dec.get("state")
            if declared not in DECISION_STATES:
                self.add("error", "E4-DECISION.STATE", f"invalid state: {declared}", did)
                continue
            att = atts.get(dec.get("attestation"))
            pol = policies.get(dec.get("policy"))
            if att is None or pol is None:
                self.add("error", "E4-DECISION.REF", "decision reference unresolved", did)
                continue
            if self.maps["delegations"] or (pol.get("require_revocation_evaluation") and self.maps["revocations"]):
                computed = "partially-evaluated"
            else:
                computed, _ = self.direct_root_auth(att, pol)
            if declared == "authenticated" and computed != "authenticated":
                self.add("error", "E4-DECISION.OVERCLAIM", f"declared authenticated but recomputed {computed}", did)
            elif declared != computed:
                self.add("warning", "E4-DECISION.DIFFER", f"declared {declared}; reference checker computes {computed}", did)

    def run(self) -> dict[str, Any]:
        if self.load():
            self.check_refs()
            self.check_delegation_graph()
            self.check_decisions()
        findings = sorted(self.findings, key=lambda f: (f.severity, f.code, f.path, f.message))
        errors = sum(f.severity == "error" for f in findings)
        structural = "non-conformant" if errors else "conformant"
        if self.crypto_provider == "none":
            crypto = "not-evaluated"
        elif self.crypto_invalid:
            crypto = "invalid"
        elif self.crypto_attempted and self.crypto_valid == self.crypto_attempted:
            crypto = "verified"
        elif self.crypto_unavailable:
            crypto = "unavailable"
        else:
            crypto = "not-evaluated"
        auth_claims = [d for d in self.maps.get("decisions", {}).values() if d.get("state") == "authenticated"]
        authentication = "claimed" if auth_claims else "not-applicable"
        overall = structural if structural != "conformant" else "conformant"
        return {
            "tool": "eigiib-trust-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": structural,
            "crypto_result": crypto,
            "authentication_result": authentication,
            "overall_result": overall,
            "findings": [asdict(f) for f in findings],
        }

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check EIGIIB-E4 trust and attestation registry")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--registry", default="conformance/trust.json")
    ap.add_argument("--crypto-provider", choices=["none", "openssl"], default="none")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    root = Path(ns.root).resolve()
    if not root.is_dir():
        return 64
    rp = Path(ns.registry)
    if rp.is_absolute() or ".." in rp.parts:
        return 64
    report = Checker(root, rp, ns.crypto_provider).run()
    if ns.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"structural: {report['structural_result']}")
        print(f"crypto:     {report['crypto_result']}")
        print(f"auth:       {report['authentication_result']}")
        for f in report["findings"]:
            print(f"{f['severity'].upper()} {f['code']} [{f['path']}]: {f['message']}")
    return 1 if report["structural_result"] == "non-conformant" else 0

if __name__ == "__main__":
    raise SystemExit(main())
