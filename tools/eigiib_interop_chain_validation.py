"""Closed-manifest and cross-capsule validation for EIGIIB P1-A4."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from eigiib_interop_chain_contract import *


def prepare_chain(root: Path, manifest: Any):
    root = root.resolve()
    findings: list[Finding] = []
    stages = {"manifest": "not-evaluated", "p1a1": "not-evaluated", "p1a2": "not-evaluated", "p1a3": "not-evaluated", "cross": "not-evaluated"}

    def add(code, path, message):
        findings.append(Finding("error", code, path, message))

    if not isinstance(manifest, dict):
        add("P1A4.MANIFEST.TYPE", "", "manifest root must be an object")
        return findings, stages, None, {}
    if set(manifest) != TOP_FIELDS:
        add("P1A4.MANIFEST.FIELD", "", "manifest fields do not match P1-A4")
    if manifest.get("standard") != STANDARD or manifest.get("profile") != PROFILE or manifest.get("status") != CHAIN_STATUS:
        add("P1A4.MANIFEST.CONST", "", "standard, profile, or status mismatch")

    components = manifest.get("components")
    component_map = {}
    if not isinstance(components, list) or [x.get("id") if isinstance(x, dict) else None for x in components] != COMPONENT_IDS:
        add("P1A4.COMPONENT.ORDER", "components", "components must appear once in the fixed P1-A4 order")
    else:
        for i, item in enumerate(components):
            loc = f"components[{i}]"
            if set(item) != COMPONENT_FIELDS:
                add("P1A4.COMPONENT.FIELD", loc, "component fields do not match P1-A4")
                continue
            cid = item["id"]
            component_map[cid] = item
            if item.get("path") != COMPONENT_PATHS[cid] or item.get("standard") != COMPONENT_STANDARDS[cid]:
                add("P1A4.COMPONENT.CONTRACT", loc, "component path or standard differs from fixed contract")
            if not valid_identity(item.get("identity")):
                add("P1A4.COMPONENT.IDENTITY", f"{loc}.identity", "invalid component identity")

    keys = manifest.get("keys")
    key_map = {}
    if not isinstance(keys, list) or [x.get("id") if isinstance(x, dict) else None for x in keys] != KEY_IDS:
        add("P1A4.KEY.ORDER", "keys", "keys must appear once in the fixed P1-A4 order")
    else:
        for i, item in enumerate(keys):
            loc = f"keys[{i}]"
            if set(item) != KEY_FIELDS:
                add("P1A4.KEY.FIELD", loc, "key fields do not match P1-A4")
                continue
            kid = item["id"]
            key_map[kid] = item
            path, role = KEY_CONTRACT[kid]
            if item.get("path") != path or item.get("role") != role:
                add("P1A4.KEY.CONTRACT", loc, "key path or role differs from fixed contract")
            if not valid_identity(item.get("spkiIdentity")):
                add("P1A4.KEY.IDENTITY", f"{loc}.spkiIdentity", "invalid SPKI identity")

    replay = manifest.get("replay")
    chain_id = None
    if not isinstance(replay, dict) or set(replay) != REPLAY_FIELDS:
        add("P1A4.REPLAY.FIELD", "replay", "replay fields do not match P1-A4")
    else:
        if replay.get("order") != REPLAY_ORDER or replay.get("subjectName") != SUBJECT_NAME:
            add("P1A4.REPLAY.CONTRACT", "replay", "replay order or subject name mismatch")
        checkers = replay.get("checkers")
        if not isinstance(checkers, list) or [x.get("id") if isinstance(x, dict) else None for x in checkers] != REPLAY_ORDER:
            add("P1A4.CHECKER.ORDER", "replay.checkers", "checkers must match fixed replay order")
        else:
            for i, checker in enumerate(checkers):
                loc = f"replay.checkers[{i}]"
                if set(checker) != CHECKER_FIELDS:
                    add("P1A4.CHECKER.FIELD", loc, "checker fields do not match P1-A4")
                    continue
                path, version = CHECKER_CONTRACT[checker["id"]]
                if checker.get("path") != path or checker.get("toolVersion") != version:
                    add("P1A4.CHECKER.CONTRACT", loc, "checker path or version mismatch")
        chain_id = replay.get("chainIdentity")
        if not valid_identity(chain_id):
            add("P1A4.CHAIN.IDENTITY", "replay.chainIdentity", "invalid chain identity")
        elif chain_id != identity(canonical_json_bytes(chain_descriptor(manifest))):
            add("P1A4.CHAIN.IDENTITY_MISMATCH", "replay.chainIdentity", "chain identity does not match canonical descriptor")

    boundary = manifest.get("claimBoundary")
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_FIELDS:
        add("P1A4.BOUNDARY.FIELD", "claimBoundary", "claimBoundary fields do not match P1-A4")
    else:
        if boundary.get("authority") != "p1_chain_contract" or boundary.get("compositionOnly") is not True:
            add("P1A4.BOUNDARY.MODE", "claimBoundary", "boundary authority or composition mode mismatch")
        if boundary.get("doesNotImply") != BOUNDARIES:
            add("P1A4.BOUNDARY.WEAKENED", "claimBoundary.doesNotImply", "negative implication boundary must match P1-A4 exactly")
    if findings:
        return findings, stages, chain_id if valid_identity(chain_id) else None, {}

    stages["manifest"] = "conformant"
    paths = {}
    for cid, item in component_map.items():
        try:
            path = confined(root, item["path"])
            if not path.is_file():
                raise ValueError("file is missing")
            paths[cid] = path
        except ValueError as exc:
            add("P1A4.COMPONENT.PATH", item["path"], str(exc))
    for kid, item in key_map.items():
        try:
            path = confined(root, item["path"])
            if not path.is_file():
                raise ValueError("file is missing")
            paths[kid] = path
        except ValueError as exc:
            add("P1A4.KEY.PATH", item["path"], str(exc))
    for cid in ("m0-a2-report", "p1-a2-bundle"):
        if cid in paths and component_map[cid]["identity"] != identity(paths[cid].read_bytes()):
            add("P1A4.COMPONENT.IDENTITY_MISMATCH", component_map[cid]["path"], "declared identity differs from exact file bytes")

    parsed = {}
    for cid in ("m0-a2-report", "p1-a1-statement", "p1-a2-bundle", "p1-a3-signed-statement"):
        if cid in paths:
            try:
                parsed[cid] = strict_json_loads(paths[cid].read_bytes(), f"P1A4.{cid}.PARSE")
            except ValueError as exc:
                add("P1A4.COMPONENT.PARSE", component_map[cid]["path"], str(exc))
    for cid in parsed:
        if isinstance(parsed[cid], dict) and parsed[cid].get("standard") != COMPONENT_STANDARDS[cid]:
            add("P1A4.COMPONENT.STANDARD", component_map[cid]["path"], f"component standard must be {COMPONENT_STANDARDS[cid]}")

    p1a1, p1a2, p1a3 = parsed.get("p1-a1-statement"), parsed.get("p1-a2-bundle"), parsed.get("p1-a3-signed-statement")
    if isinstance(p1a1, dict):
        transported = (((p1a1.get("statement") or {}).get("predicate") or {}).get("aggregateReport") or {}).get("identity")
        if transported != component_map["m0-a2-report"]["identity"]:
            add("P1A4.BINDING.M0A2_P1A1", "p1-a1.statement.predicate.aggregateReport.identity", "P1-A1 does not bind the declared M0-A2 identity")
    if isinstance(p1a2, dict):
        binding = p1a2.get("binding") or {}
        if binding.get("p1A1Statement") != component_map["p1-a1-statement"]["identity"]:
            add("P1A4.BINDING.P1A1_P1A2", "p1-a2.binding.p1A1Statement", "P1-A2 does not bind the declared P1-A1 Statement identity")
        if binding.get("publicKeySpki") != key_map["p1-a2-public-key"]["spkiIdentity"]:
            add("P1A4.BINDING.P1A2_KEY", "p1-a2.binding.publicKeySpki", "P1-A2 signer key binding mismatch")
    if isinstance(p1a3, dict):
        binding, signed, receipt = p1a3.get("binding") or {}, p1a3.get("signedStatement") or {}, p1a3.get("receipt") or {}
        checks = [
            (binding.get("p1A2Bundle"), component_map["p1-a2-bundle"]["identity"], "P1A4.BINDING.P1A2_P1A3", "p1-a3.binding.p1A2Bundle"),
            (signed.get("identity"), component_map["p1-a3-signed-statement"]["identity"], "P1A4.BINDING.SIGNED_STATEMENT", "p1-a3.signedStatement.identity"),
            (receipt.get("identity"), component_map["p1-a3-receipt"]["identity"], "P1A4.BINDING.RECEIPT", "p1-a3.receipt.identity"),
            (signed.get("issuerKeySpki"), key_map["p1-a3-issuer-key"]["spkiIdentity"], "P1A4.BINDING.ISSUER_KEY", "p1-a3.signedStatement.issuerKeySpki"),
            (receipt.get("transparencyServiceKeySpki"), key_map["p1-a3-transparency-service-key"]["spkiIdentity"], "P1A4.BINDING.TS_KEY", "p1-a3.receipt.transparencyServiceKeySpki"),
        ]
        for observed, expected, code, path in checks:
            if observed != expected:
                add(code, path, "cross-capsule identity binding mismatch")
    if not findings:
        stages["cross"] = "conformant"
    return findings, stages, chain_id, paths
