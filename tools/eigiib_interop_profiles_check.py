#!/usr/bin/env python3
"""Static checker for EIGIIB M0-A3 external interoperability profiles."""
from __future__ import annotations

import argparse
import json
import tomllib
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-M0-A3-1.0"

REFERENCE_MODES = {"versioned-reference", "exact-draft", "moving-reference"}
PROFILE_STATES = {"research", "specified", "implemented", "validated"}
RELATIONS = {"transports", "represents", "supplies-evidence", "authenticates", "time-binds", "indexes", "identifies", "policy-evaluates"}
STRENGTHS = {"transport-only", "bounded-semantic", "exact-semantic"}
FORBIDDEN_VERSION_TOKENS = {"latest", "main", "master"}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Checker:
    def __init__(self, root: Path, registry: Path, config: Path):
        self.root = root.resolve()
        self.registry_path = registry
        self.config_path = config
        self.findings: list[Finding] = []
        self.spec_count = 0
        self.profile_count = 0
        self.validated_count = 0

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def confined(self, rel: Path, code: str, *, must_exist: bool = False) -> Path | None:
        if rel.is_absolute():
            self.add("error", f"{code}.PATH", "path must be repository-relative", str(rel))
            return None
        p = (self.root / rel).resolve(strict=False)
        try:
            p.relative_to(self.root)
        except ValueError:
            self.add("error", f"{code}.PATH", "path escapes repository root", str(rel))
            return None
        if must_exist and (not p.exists() or not p.is_file()):
            self.add("error", f"{code}.MISSING", "referenced file is missing", str(rel))
            return None
        return p

    def load_json(self, rel: Path, code: str) -> dict[str, Any] | None:
        p = self.confined(rel, code, must_exist=True)
        if p is None:
            return None
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", f"{code}.PARSE", str(exc), str(rel))
            return None
        if not isinstance(obj, dict):
            self.add("error", f"{code}.TYPE", "JSON root must be an object", str(rel))
            return None
        return obj

    def load_authorities(self) -> set[str]:
        p = self.confined(self.config_path, "M0A3.CONFIG", must_exist=True)
        if p is None:
            return set()
        try:
            obj = tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "M0A3.CONFIG.PARSE", str(exc), str(self.config_path))
            return set()
        auth = obj.get("authorities")
        if not isinstance(auth, dict):
            self.add("error", "M0A3.CONFIG.AUTHORITIES", "[authorities] table is missing", str(self.config_path))
            return set()
        return {k for k, v in auth.items() if isinstance(k, str) and isinstance(v, str) and v}

    @staticmethod
    def parse_date(value: Any) -> date | None:
        if not isinstance(value, str):
            return None
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None

    def check_specs(self, obj: dict[str, Any], as_of: date | None) -> dict[str, dict[str, Any]]:
        items = obj.get("external_specs")
        if not isinstance(items, list):
            self.add("error", "M0A3.SPECS.TYPE", "external_specs must be an array", str(self.registry_path))
            return {}
        out: dict[str, dict[str, Any]] = {}
        for i, spec in enumerate(items):
            loc = f"external_specs[{i}]"
            if not isinstance(spec, dict):
                self.add("error", "M0A3.SPEC.TYPE", "spec entry must be an object", loc)
                continue
            sid = spec.get("id")
            if not isinstance(sid, str) or not sid:
                self.add("error", "M0A3.SPEC.ID", "spec id must be non-empty string", loc)
                continue
            if sid in out:
                self.add("error", "M0A3.SPEC.DUPLICATE", f"duplicate spec id: {sid}", loc)
                continue
            out[sid] = spec
            self.spec_count += 1

            version = spec.get("version")
            if not isinstance(version, str) or not version.strip():
                self.add("error", "M0A3.SPEC.VERSION", "version must be non-empty string", loc)
                continue
            lower_version = version.lower()
            if lower_version in FORBIDDEN_VERSION_TOKENS or any(token == lower_version.strip("v") for token in FORBIDDEN_VERSION_TOKENS):
                self.add("error", "M0A3.SPEC.FLOATING_VERSION", "version must not be latest/main/master", loc)

            uri = spec.get("canonical_uri")
            if not isinstance(uri, str) or urlparse(uri).scheme != "https" or not urlparse(uri).netloc:
                self.add("error", "M0A3.SPEC.URI", "canonical_uri must be absolute HTTPS URI", loc)
                uri = ""
            if any(marker in uri.lower() for marker in ("/latest/", "/main/", "/master/")) and spec.get("reference_mode") != "moving-reference":
                self.add("error", "M0A3.SPEC.FLOATING_URI", "non-moving reference URI contains latest/main/master", loc)

            mode = spec.get("reference_mode")
            if mode not in REFERENCE_MODES:
                self.add("error", "M0A3.SPEC.MODE", "invalid reference_mode", loc)
            if mode == "versioned-reference" and version not in uri and f"v{version}" not in uri:
                self.add("error", "M0A3.SPEC.VERSION_URI", "versioned-reference URI does not expose declared version", loc)
            if mode == "exact-draft":
                if spec.get("status") != "draft":
                    self.add("error", "M0A3.SPEC.DRAFT_STATUS", "exact-draft reference must have draft status", loc)
                if version not in uri:
                    self.add("error", "M0A3.SPEC.DRAFT_URI", "exact draft revision must appear in canonical_uri", loc)

            observed = self.parse_date(spec.get("observed_on"))
            if observed is None:
                self.add("error", "M0A3.SPEC.DATE", "observed_on must be ISO date", loc)
            elif as_of is not None and observed > as_of:
                self.add("error", "M0A3.SPEC.DATE_ORDER", "observed_on cannot be after registry as_of", loc)
        return out

    def check_profiles(self, obj: dict[str, Any], specs: dict[str, dict[str, Any]], authorities: set[str]) -> None:
        items = obj.get("profiles")
        if not isinstance(items, list):
            self.add("error", "M0A3.PROFILES.TYPE", "profiles must be an array", str(self.registry_path))
            return
        seen: set[str] = set()
        for i, profile in enumerate(items):
            loc = f"profiles[{i}]"
            if not isinstance(profile, dict):
                self.add("error", "M0A3.PROFILE.TYPE", "profile entry must be an object", loc)
                continue
            pid = profile.get("id")
            if not isinstance(pid, str) or not pid:
                self.add("error", "M0A3.PROFILE.ID", "profile id must be non-empty string", loc)
                continue
            if pid in seen:
                self.add("error", "M0A3.PROFILE.DUPLICATE", f"duplicate profile id: {pid}", loc)
                continue
            seen.add(pid)
            self.profile_count += 1

            state = profile.get("state")
            if state not in PROFILE_STATES:
                self.add("error", "M0A3.PROFILE.STATE", "invalid profile state", loc)
                continue
            if state == "validated":
                self.validated_count += 1

            sid = profile.get("external_spec")
            spec = specs.get(sid) if isinstance(sid, str) else None
            if spec is None:
                self.add("error", "M0A3.PROFILE.SPEC", "external_spec does not resolve", loc)
            elif state == "validated" and (spec.get("reference_mode") == "moving-reference" or spec.get("status") == "draft"):
                self.add("error", "M0A3.PROFILE.UNSTABLE_VALIDATION", "validated profile cannot rely on moving reference or draft spec", loc)

            auths = profile.get("eigiib_authorities")
            if not isinstance(auths, list) or not auths:
                self.add("error", "M0A3.PROFILE.AUTHORITIES", "eigiib_authorities must be non-empty array", loc)
            else:
                if len(auths) != len(set(auths)):
                    self.add("error", "M0A3.PROFILE.AUTH_DUPLICATE", "duplicate EIGIIB authority", loc)
                for authority in auths:
                    if authority not in authorities:
                        self.add("error", "M0A3.PROFILE.AUTHORITY_REF", f"unknown EIGIIB authority: {authority}", loc)

            mappings = profile.get("mappings")
            if not isinstance(mappings, list) or not mappings:
                self.add("error", "M0A3.PROFILE.MAPPINGS", "mappings must be non-empty array", loc)
                mappings = []
            seen_map: set[tuple[str, str, str]] = set()
            for j, mapping in enumerate(mappings):
                mloc = f"{loc}.mappings[{j}]"
                if not isinstance(mapping, dict):
                    self.add("error", "M0A3.MAPPING.TYPE", "mapping must be an object", mloc)
                    continue
                ext = mapping.get("external_element")
                eig = mapping.get("eigiib_element")
                rel = mapping.get("relation")
                strength = mapping.get("strength")
                if not isinstance(ext, str) or not ext or not isinstance(eig, str) or not eig:
                    self.add("error", "M0A3.MAPPING.ELEMENT", "mapping elements must be non-empty strings", mloc)
                if rel not in RELATIONS:
                    self.add("error", "M0A3.MAPPING.RELATION", "invalid mapping relation", mloc)
                if strength not in STRENGTHS:
                    self.add("error", "M0A3.MAPPING.STRENGTH", "invalid mapping strength", mloc)
                key = (str(ext), str(eig), str(rel))
                if key in seen_map:
                    self.add("error", "M0A3.MAPPING.DUPLICATE", "duplicate mapping relation", mloc)
                seen_map.add(key)
                if strength == "exact-semantic" and state != "validated":
                    self.add("error", "M0A3.MAPPING.EXACT_UNVALIDATED", "exact-semantic mapping requires validated profile", mloc)

            bounds = profile.get("does_not_imply")
            if not isinstance(bounds, list) or not bounds or any(not isinstance(x, str) or not x for x in bounds):
                self.add("error", "M0A3.PROFILE.BOUNDARY", "does_not_imply must contain non-empty boundaries", loc)
            elif len(bounds) != len(set(bounds)):
                self.add("error", "M0A3.PROFILE.BOUNDARY_DUPLICATE", "duplicate does_not_imply boundary", loc)

            evidence = profile.get("evidence")
            if not isinstance(evidence, list):
                self.add("error", "M0A3.PROFILE.EVIDENCE", "evidence must be an array", loc)
                evidence = []
            if state in {"implemented", "validated"} and not evidence:
                self.add("error", "M0A3.PROFILE.EVIDENCE_REQUIRED", f"{state} profile requires evidence paths", loc)
            for item in evidence:
                if not isinstance(item, str) or not item:
                    self.add("error", "M0A3.PROFILE.EVIDENCE_ITEM", "evidence item must be non-empty path", loc)
                    continue
                self.confined(Path(item), "M0A3.PROFILE.EVIDENCE", must_exist=True)

    def run(self) -> dict[str, Any]:
        obj = self.load_json(self.registry_path, "M0A3.REGISTRY")
        authorities = self.load_authorities()
        if obj is not None:
            if obj.get("standard") != STANDARD:
                self.add("error", "M0A3.STANDARD", f"standard must be {STANDARD}", str(self.registry_path))
            as_of = self.parse_date(obj.get("as_of"))
            if as_of is None:
                self.add("error", "M0A3.AS_OF", "as_of must be ISO date", str(self.registry_path))
            specs = self.check_specs(obj, as_of)
            self.check_profiles(obj, specs, authorities)
        failed = any(f.severity == "error" for f in self.findings)
        return {
            "tool": "eigiib-interop-profiles-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if failed else "conformant",
            "external_spec_count": self.spec_count,
            "profile_count": self.profile_count,
            "validated_profile_count": self.validated_count,
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--registry", default="conformance/interop-profiles.json")
    ap.add_argument("--config", default="EIGIIB.toml")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = Checker(Path(args.root), Path(args.registry), Path(args.config)).run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
