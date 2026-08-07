#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from pathlib import Path

EXPECTED_CLASSES = {
    "D0": ("Public News", "public", 0, "news"),
    "D1": ("Public Normative", "public", 0, "normative"),
    "D2": ("Public Open Implementation", "public", 0, "open-implementation"),
    "D3": ("Controlled Engineering", "controlled", 1, "engineering"),
    "D4": ("Restricted Critical", "restricted", 2, "restricted-critical"),
    "D5": ("Operational Secret", "secret", 3, "operational-secret"),
}
EXPECTED_CHANNELS = {
    "local-authority": ("local-authority", "internal", ["D0","D1","D2","D3","D4","D5"], True, "not-applicable", False, False),
    "public-facade": ("public-facade", "outbound", ["D0","D1","D2"], False, "not-applicable", True, False),
    "private-bridge-out": ("private-bridge-out", "outbound", ["D0","D1","D2","D3"], False, "not-applicable", True, False),
    "private-bridge-return": ("private-bridge-return", "inbound", ["D0","D1","D2","D3"], False, "quarantined", False, False),
    "restricted-review": ("restricted-review", "bidirectional", ["D4"], False, "quarantined", True, True),
}
EXPECTED_RULES = {
    "publicClasses": ["D0","D1","D2"],
    "bridgeForbiddenClasses": ["D5"],
    "directPublicReleaseForbiddenClasses": ["D3","D4","D5"],
    "classChangeRequiresNewIdentity": True,
    "declassificationRequiresDerivedArtifact": True,
    "declassificationRequiresLocalDecisionAuthority": True,
    "inboundBridgeDefaultState": "quarantined",
    "bridgeRootAuthorityForbidden": True,
    "d5ExternalArtifactMetadataForbidden": True,
    "productionSecretMaterialInGitForbidden": True,
    "restrictedExternalCommitmentMode": "opaque-randomized",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOP = {"standard","profileState","registryScope","classes","channels","authorities","rules","artifacts","derivations"}

def _finding(out, code, detail=""):
    out.append(code if not detail else f"{code}:{detail}")

def validate(data):
    f = []
    if not isinstance(data, dict) or set(data) != TOP:
        _finding(f, "top-level-shape")
        if not isinstance(data, dict): return sorted(f)
    if data.get("standard") != "EIGIIB-IDP-A1-0.1": _finding(f, "standard")
    if data.get("profileState") not in {"draft","active","retired"}: _finding(f, "profile-state")
    if data.get("registryScope") not in {"structural-only","operational"}: _finding(f, "registry-scope")

    classes = data.get("classes") if isinstance(data.get("classes"), list) else []
    seen = set()
    for item in classes:
        if not isinstance(item, dict): _finding(f, "class-shape"); continue
        cid = item.get("id")
        if cid in seen: _finding(f, "class-duplicate", str(cid))
        seen.add(cid)
        exp = EXPECTED_CLASSES.get(cid)
        got = (item.get("name"), item.get("visibility"), item.get("restrictionRank"), item.get("surface"))
        if exp is None or got != exp or set(item) != {"id","name","visibility","restrictionRank","surface"}:
            _finding(f, "class-policy", str(cid))
    if seen != set(EXPECTED_CLASSES): _finding(f, "class-set")

    channels = data.get("channels") if isinstance(data.get("channels"), list) else []
    chmap = {}
    for item in channels:
        if not isinstance(item, dict): _finding(f, "channel-shape"); continue
        cid = item.get("id")
        if cid in chmap: _finding(f, "channel-duplicate", str(cid))
        chmap[cid] = item
        exp = EXPECTED_CHANNELS.get(cid)
        got = (item.get("kind"), item.get("direction"), item.get("allowedClasses"), item.get("authoritativeRoot"), item.get("ingressDisposition"), item.get("requiresDerivedArtifact"), item.get("namedAudienceRequired"))
        if exp is None or got != exp:
            _finding(f, "channel-policy", str(cid))
    if set(chmap) != set(EXPECTED_CHANNELS): _finding(f, "channel-set")
    roots = [c.get("id") for c in channels if isinstance(c, dict) and c.get("authoritativeRoot") is True]
    if roots != ["local-authority"]: _finding(f, "root-authority-channel")

    authorities = data.get("authorities") if isinstance(data.get("authorities"), list) else []
    amap = {}
    for a in authorities:
        if not isinstance(a, dict) or set(a) != {"id","role","bindingState"}: _finding(f, "authority-shape"); continue
        aid = a.get("id")
        if aid in amap: _finding(f, "authority-duplicate", str(aid))
        amap[aid] = a
    required_roles = {"l0-local-authority":"root-authority","idp-disclosure-authority":"disclosure-authority","public-news-publisher":"publisher"}
    for aid, role in required_roles.items():
        if amap.get(aid, {}).get("role") != role: _finding(f, "authority-policy", aid)
    if data.get("rules") != EXPECTED_RULES: _finding(f, "rules")

    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), list) else []
    art = {}
    for a in artifacts:
        if not isinstance(a, dict): _finding(f, "artifact-shape"); continue
        aid = a.get("id")
        if aid in art: _finding(f, "artifact-duplicate", str(aid))
        art[aid] = a
        cls, channel, auth = a.get("classification"), a.get("channelId"), a.get("authorityId")
        if cls not in EXPECTED_CLASSES: _finding(f, "artifact-class", str(aid)); continue
        if channel not in chmap: _finding(f, "artifact-channel", str(aid)); continue
        if auth not in amap: _finding(f, "artifact-authority", str(aid))
        if cls not in chmap[channel].get("allowedClasses", []): _finding(f, "class-channel-forbidden", str(aid))
        if cls == "D5" and channel != "local-authority": _finding(f, "d5-external-forbidden", str(aid))
        if channel == "private-bridge-return" and a.get("state") != "quarantined": _finding(f, "return-not-quarantined", str(aid))
        if channel == "restricted-review":
            if cls != "D4": _finding(f, "restricted-review-class", str(aid))
            if not a.get("namedAudience"): _finding(f, "restricted-review-audience", str(aid))
            if a.get("commitmentMode") != "opaque-randomized": _finding(f, "restricted-raw-digest-forbidden", str(aid))
        if channel == "public-facade" and cls not in {"D0","D1","D2"}: _finding(f, "public-class-forbidden", str(aid))
        mode, commitment = a.get("commitmentMode"), a.get("commitment")
        if mode == "none" and commitment is not None: _finding(f, "commitment-none-mismatch", str(aid))
        if mode in {"content-digest","opaque-randomized"} and (not isinstance(commitment, str) or not HEX64.fullmatch(commitment)):
            _finding(f, "commitment-format", str(aid))
        if data.get("registryScope") == "structural-only" and a.get("synthetic") is not True:
            _finding(f, "structural-registry-production-artifact", str(aid))

    derivations = data.get("derivations") if isinstance(data.get("derivations"), list) else []
    dids = set()
    pairset = set()
    for d in derivations:
        if not isinstance(d, dict): _finding(f, "derivation-shape"); continue
        did = d.get("id")
        if did in dids: _finding(f, "derivation-duplicate", str(did))
        dids.add(did)
        sid, tid = d.get("sourceArtifactId"), d.get("derivedArtifactId")
        if sid == tid: _finding(f, "same-identity-class-change", str(did))
        pair = (sid, tid)
        if pair in pairset: _finding(f, "derivation-pair-duplicate", str(did))
        pairset.add(pair)
        s, t = art.get(sid), art.get(tid)
        if s is None or t is None: _finding(f, "derivation-artifact-missing", str(did)); continue
        if d.get("sourceClass") != s.get("classification") or d.get("targetClass") != t.get("classification"):
            _finding(f, "derivation-class-binding", str(did))
        if t.get("derivedFrom") != sid: _finding(f, "derived-from-binding", str(did))
        if s.get("classification") != t.get("classification") and sid == tid:
            _finding(f, "same-identity-class-change", str(did))
        sr = EXPECTED_CLASSES[s.get("classification")][2]; tr = EXPECTED_CLASSES[t.get("classification")][2]
        if s.get("classification") == "D5" and t.get("classification") != "D5":
            _finding(f, "d5-outward-derivation-forbidden", str(did))
        if sr > tr:
            if d.get("method") != "minimized-derivation": _finding(f, "declass-method", str(did))
            if d.get("state") != "approved": _finding(f, "declass-not-approved", str(did))
            if not isinstance(d.get("approvalIds"), list) or not d.get("approvalIds"): _finding(f, "declass-approval-missing", str(did))
            if not isinstance(d.get("claimBoundary"), str) or not d.get("claimBoundary").strip(): _finding(f, "declass-claim-boundary-missing", str(did))
            if amap.get(d.get("authorityId"), {}).get("role") != "disclosure-authority": _finding(f, "declass-authority", str(did))
        if s.get("classification") != t.get("classification") and sid == tid:
            _finding(f, "class-change-new-identity-required", str(did))

    # Every explicit class-changing derived artifact needs exactly one derivation.
    by_target = {}
    for d in derivations:
        if isinstance(d, dict): by_target.setdefault(d.get("derivedArtifactId"), []).append(d)
    for aid, a in art.items():
        src = a.get("derivedFrom")
        if src is not None and src in art and art[src].get("classification") != a.get("classification"):
            if len(by_target.get(aid, [])) != 1: _finding(f, "class-change-derivation-required", str(aid))
    return sorted(set(f))

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("registry"); ap.add_argument("--json", action="store_true"); ap.add_argument("--require-conformant", action="store_true")
    ns = ap.parse_args(); data = json.loads(Path(ns.registry).read_text(encoding="utf-8")); findings = validate(data)
    result = {"standard":"EIGIIB-IDP-A1-0.1","result":"CONFORMANT" if not findings else "NON_CONFORMANT","findings":findings}
    print(json.dumps(result, sort_keys=True) if ns.json else result["result"] + ("\n" + "\n".join(findings) if findings else ""))
    return 1 if ns.require_conformant and findings else 0
if __name__ == "__main__": raise SystemExit(main())
