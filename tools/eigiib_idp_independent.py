#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from pathlib import Path
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CLASS = {"D0":0,"D1":0,"D2":0,"D3":1,"D4":2,"D5":3}
PUBLIC = {"D0","D1","D2"}
CHANNEL_ALLOWED = {
 "local-authority": set(CLASS), "public-facade": PUBLIC,
 "private-bridge-out": {"D0","D1","D2","D3"},
 "private-bridge-return": {"D0","D1","D2","D3"},
 "restricted-review": {"D4"},
}

def validate(x):
    out = set()
    if not isinstance(x, dict): return ["top-level-shape"]
    if x.get("standard") != "EIGIIB-IDP-A1-0.1": out.add("standard")
    expected_ids = ["D0","D1","D2","D3","D4","D5"]
    if sorted(c.get("id") for c in x.get("classes",[]) if isinstance(c,dict)) != expected_ids: out.add("class-set")
    expected_class_tuples = {
      "D0":("Public News","public",0,"news"),"D1":("Public Normative","public",0,"normative"),"D2":("Public Open Implementation","public",0,"open-implementation"),
      "D3":("Controlled Engineering","controlled",1,"engineering"),"D4":("Restricted Critical","restricted",2,"restricted-critical"),"D5":("Operational Secret","secret",3,"operational-secret")}
    for c in x.get("classes",[]):
        if not isinstance(c,dict): out.add("class-shape"); continue
        cid=c.get("id"); tup=(c.get("name"),c.get("visibility"),c.get("restrictionRank"),c.get("surface"))
        if expected_class_tuples.get(cid)!=tup: out.add(f"class-policy:{cid}")
    cmap={c.get("id"):c for c in x.get("channels",[]) if isinstance(c,dict)}
    if set(cmap)!=set(CHANNEL_ALLOWED): out.add("channel-set")
    roots=[k for k,v in cmap.items() if v.get("authoritativeRoot") is True]
    if roots != ["local-authority"]: out.add("root-authority-channel")
    channel_expect={
      "local-authority":("local-authority","internal",["D0","D1","D2","D3","D4","D5"],True,"not-applicable",False,False),
      "public-facade":("public-facade","outbound",["D0","D1","D2"],False,"not-applicable",True,False),
      "private-bridge-out":("private-bridge-out","outbound",["D0","D1","D2","D3"],False,"not-applicable",True,False),
      "private-bridge-return":("private-bridge-return","inbound",["D0","D1","D2","D3"],False,"quarantined",False,False),
      "restricted-review":("restricted-review","bidirectional",["D4"],False,"quarantined",True,True)}
    for k,v in cmap.items():
        tup=(v.get("kind"),v.get("direction"),v.get("allowedClasses"),v.get("authoritativeRoot"),v.get("ingressDisposition"),v.get("requiresDerivedArtifact"),v.get("namedAudienceRequired"))
        if channel_expect.get(k)!=tup: out.add(f"channel-policy:{k}")
    amap={a.get("id"):a for a in x.get("authorities",[]) if isinstance(a,dict)}
    for aid,role in {"l0-local-authority":"root-authority","idp-disclosure-authority":"disclosure-authority","public-news-publisher":"publisher"}.items():
        if amap.get(aid,{}).get("role")!=role: out.add(f"authority-policy:{aid}")
    rule=x.get("rules",{})
    if rule.get("publicClasses") != ["D0","D1","D2"] or rule.get("bridgeForbiddenClasses") != ["D5"] or rule.get("directPublicReleaseForbiddenClasses") != ["D3","D4","D5"]: out.add("rules")
    for key in ["classChangeRequiresNewIdentity","declassificationRequiresDerivedArtifact","declassificationRequiresLocalDecisionAuthority","bridgeRootAuthorityForbidden","d5ExternalArtifactMetadataForbidden","productionSecretMaterialInGitForbidden"]:
        if rule.get(key) is not True: out.add("rules")
    if rule.get("inboundBridgeDefaultState")!="quarantined" or rule.get("restrictedExternalCommitmentMode")!="opaque-randomized": out.add("rules")
    arts={}
    for a in x.get("artifacts",[]):
        if not isinstance(a,dict): out.add("artifact-shape"); continue
        aid=a.get("id")
        if aid in arts: out.add(f"artifact-duplicate:{aid}")
        arts[aid]=a; cls=a.get("classification"); ch=a.get("channelId")
        if cls not in CLASS: out.add(f"artifact-class:{aid}"); continue
        if ch not in CHANNEL_ALLOWED: out.add(f"artifact-channel:{aid}"); continue
        if cls not in CHANNEL_ALLOWED[ch]: out.add(f"class-channel-forbidden:{aid}")
        if cls=="D5" and ch!="local-authority": out.add(f"d5-external-forbidden:{aid}")
        if ch=="public-facade" and cls not in PUBLIC: out.add(f"public-class-forbidden:{aid}")
        if ch=="private-bridge-return" and a.get("state")!="quarantined": out.add(f"return-not-quarantined:{aid}")
        if ch=="restricted-review":
            if not a.get("namedAudience"): out.add(f"restricted-review-audience:{aid}")
            if a.get("commitmentMode")!="opaque-randomized": out.add(f"restricted-raw-digest-forbidden:{aid}")
        mode=a.get("commitmentMode"); val=a.get("commitment")
        if mode=="none" and val is not None: out.add(f"commitment-none-mismatch:{aid}")
        if mode in {"content-digest","opaque-randomized"} and (not isinstance(val,str) or not HEX64.fullmatch(val)): out.add(f"commitment-format:{aid}")
        if x.get("registryScope")=="structural-only" and a.get("synthetic") is not True: out.add(f"structural-registry-production-artifact:{aid}")
    targets={}
    for d in x.get("derivations",[]):
        if not isinstance(d,dict): out.add("derivation-shape"); continue
        sid=d.get("sourceArtifactId"); tid=d.get("derivedArtifactId"); targets.setdefault(tid,0); targets[tid]+=1
        if sid==tid: out.add(f"same-identity-class-change:{d.get('id')}")
        s=arts.get(sid); t=arts.get(tid)
        if s is None or t is None: out.add(f"derivation-artifact-missing:{d.get('id')}"); continue
        if d.get("sourceClass")!=s.get("classification") or d.get("targetClass")!=t.get("classification"): out.add(f"derivation-class-binding:{d.get('id')}")
        if t.get("derivedFrom")!=sid: out.add(f"derived-from-binding:{d.get('id')}")
        if s.get("classification")=="D5" and t.get("classification")!="D5": out.add(f"d5-outward-derivation-forbidden:{d.get('id')}")
        if CLASS[s.get("classification")] > CLASS[t.get("classification")]:
            if d.get("method")!="minimized-derivation": out.add(f"declass-method:{d.get('id')}")
            if d.get("state")!="approved": out.add(f"declass-not-approved:{d.get('id')}")
            if not d.get("approvalIds"): out.add(f"declass-approval-missing:{d.get('id')}")
            if not str(d.get("claimBoundary","")).strip(): out.add(f"declass-claim-boundary-missing:{d.get('id')}")
            if amap.get(d.get("authorityId"),{}).get("role")!="disclosure-authority": out.add(f"declass-authority:{d.get('id')}")
    for aid,a in arts.items():
        src=a.get("derivedFrom")
        if src in arts and arts[src].get("classification")!=a.get("classification") and targets.get(aid)!=1: out.add(f"class-change-derivation-required:{aid}")
    return sorted(out)

def main():
    p=argparse.ArgumentParser(); p.add_argument("registry"); p.add_argument("--json",action="store_true"); p.add_argument("--require-conformant",action="store_true"); ns=p.parse_args()
    x=json.loads(Path(ns.registry).read_text()); f=validate(x); r={"standard":"EIGIIB-IDP-A1-0.1","result":"CONFORMANT" if not f else "NON_CONFORMANT","findings":f}
    print(json.dumps(r,sort_keys=True) if ns.json else r["result"]+("\n"+"\n".join(f) if f else "")); return 1 if ns.require_conformant and f else 0
if __name__=="__main__": raise SystemExit(main())
