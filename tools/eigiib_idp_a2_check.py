#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

HEX64=re.compile(r"^[0-9a-f]{64}$")
A1={"head":"ec352636690ee22135cfc7a3d3e2067ee323f2cf","policyPath":"conformance/idp-policy.json","policyBlobSha":"7aac9aa7223eadd3739c0b59d4275eeed58bb3d1"}
ROUTES={
 "bridge-out-binding":{"channelId":"private-bridge-out","direction":"outbound","localRole":"bridge-origin","remoteRole":"bridge-peer","localPurpose":"origin","remotePurpose":"peer","protocol":"ssh","allowedClasses":["D0","D1","D2","D3"]},
 "bridge-return-binding":{"channelId":"private-bridge-return","direction":"inbound","localRole":"bridge-return-receiver","remoteRole":"bridge-return-peer","localPurpose":"receiver","remotePurpose":"peer","protocol":"ssh","allowedClasses":["D0","D1","D2","D3"]},
 "restricted-review-binding":{"channelId":"restricted-review","direction":"bidirectional","localRole":"restricted-review-origin","remoteRole":"restricted-review-peer","localPurpose":"origin","remotePurpose":"peer","protocol":"tls","allowedClasses":["D4"]}
}
RULES={"bridgeCannotAssertRootAuthority","crossRoutePrincipalReuseForbidden","crossRouteEndpointReuseForbidden","crossRoutePinsetReuseForbidden","crossRouteTransportReuseForbidden","directionBindingRequired","principalRoleBindingRequired","endpointPrincipalBindingRequired","transportChannelBindingRequired","remotePinsetBindingRequired","contextCommitmentRequired","structuralLocatorsMustRemainUnbound","structuralAuthenticatorsMustBeSynthetic","operationalBindingRequiresNonSyntheticAuthenticatorAndPins","d5BridgeTransportForbidden"}
CTX=("channelId","direction","localPrincipalId","remotePrincipalId","localEndpointId","remoteEndpointId","transportProfileId","expectedPinsetId","allowedClasses")

def canon_sha(obj):
    return hashlib.sha256((json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode()).hexdigest()

def _map(items,code,f):
    out={}
    if not isinstance(items,list): f.append(code+"-shape"); return out
    for x in items:
        if not isinstance(x,dict) or not isinstance(x.get("id"),str): f.append(code+"-shape"); continue
        if x["id"] in out: f.append(code+"-duplicate:"+x["id"])
        out[x["id"]]=x
    return out

def validate(d):
    f=[]
    if not isinstance(d,dict): return ["top-level-shape"]
    if d.get("standard")!="EIGIIB-IDP-A2-0.1": f.append("standard")
    if d.get("sourceA1")!=A1: f.append("source-a1-binding")
    if set(d.get("rules",{}))!=RULES or any(v is not True for v in d.get("rules",{}).values()): f.append("rules")
    scope=d.get("registryScope")
    if scope not in {"structural-only","operational"}: f.append("registry-scope")

    pm=_map(d.get("principals"),"principal",f); em=_map(d.get("endpoints"),"endpoint",f); sm=_map(d.get("pinsets"),"pinset",f); tm=_map(d.get("transportProfiles"),"transport",f); bm=_map(d.get("bindings"),"binding",f)
    roots=[p.get("id") for p in d.get("principals",[]) if isinstance(p,dict) and p.get("rootAuthority") is True]
    if roots!=["l0-local-authority"] or pm.get("l0-local-authority",{}).get("role")!="local-root": f.append("root-authority-principal")

    domains=set(); keys=set(); fps=set()
    for pid,p in pm.items():
        if pid!="l0-local-authority" and p.get("rootAuthority") is not False: f.append("bridge-root-authority:"+pid)
        for value,seen,code in [(p.get("controlDomainId"),domains,"principal-domain-reuse"),(p.get("authenticator",{}).get("keyId"),keys,"key-id-reuse"),(p.get("authenticator",{}).get("publicKeyFingerprint"),fps,"fingerprint-reuse")]:
            if value in seen: f.append(code+":"+pid)
            seen.add(value)
        a=p.get("authenticator",{})
        if a.get("kind")!="asymmetric-key" or a.get("fingerprintAlgorithm")!="sha256" or not HEX64.fullmatch(str(a.get("publicKeyFingerprint",""))): f.append("authenticator-policy:"+pid)
        if scope=="structural-only" and (a.get("synthetic") is not True or p.get("operationalState")!="planned"): f.append("structural-authenticator:"+pid)
        if scope=="operational" and a.get("synthetic") is not False: f.append("operational-authenticator-synthetic:"+pid)

    for eid,e in em.items():
        if e.get("expectedPrincipalId") not in pm: f.append("endpoint-principal-missing:"+eid)
        if scope=="structural-only" and (e.get("locatorState")!="unbound" or e.get("locator") is not None or e.get("operationalState")!="planned"): f.append("structural-endpoint-bound:"+eid)
        if scope=="operational" and (e.get("locatorState")!="bound" or not isinstance(e.get("locator"),str) or not e.get("locator")): f.append("operational-endpoint-unbound:"+eid)
        if e.get("side")=="local" and e.get("pinsetId") is not None: f.append("local-endpoint-pinset-forbidden:"+eid)

    allpins=set()
    for sid,s in sm.items():
        pins=s.get("pins",[])
        if s.get("algorithm")!="sha256" or not isinstance(pins,list) or not pins: f.append("pinset-policy:"+sid)
        for pin in pins:
            if not HEX64.fullmatch(str(pin)): f.append("pin-format:"+sid)
            if pin in allpins: f.append("cross-pin-reuse:"+sid)
            allpins.add(pin)
        body={k:s.get(k) for k in ("id","endpointId","algorithm","pins","synthetic")}
        if s.get("commitment")!=canon_sha(body): f.append("pinset-commitment:"+sid)
        if scope=="structural-only" and s.get("synthetic") is not True: f.append("structural-pinset:"+sid)
        if scope=="operational" and s.get("synthetic") is not False: f.append("operational-pinset-synthetic:"+sid)

    for tid,t in tm.items():
        if t.get("peerAuthentication")!="mutual-asymmetric": f.append("transport-auth:"+tid)
        for flag in ("confidentialityRequired","integrityRequired","endpointPinningRequired","channelBindingRequired"):
            if t.get(flag) is not True: f.append("transport-requirement:"+tid+"/"+flag)
        if scope=="structural-only" and t.get("operationalState")!="planned": f.append("structural-transport-active:"+tid)

    if set(bm)!=set(ROUTES): f.append("binding-set")
    usedp=set(); usede=set(); useds=set(); usedt=set()
    for bid,exp in ROUTES.items():
        b=bm.get(bid,{})
        if b.get("channelId")!=exp["channelId"]: f.append("binding-channel:"+bid)
        if b.get("direction")!=exp["direction"]: f.append("binding-direction:"+bid)
        if b.get("allowedClasses")!=exp["allowedClasses"]: f.append("binding-classes:"+bid)
        if "D5" in (b.get("allowedClasses") or []): f.append("d5-bridge-forbidden:"+bid)
        lp=pm.get(b.get("localPrincipalId"),{}); rp=pm.get(b.get("remotePrincipalId"),{})
        if lp.get("role")!=exp["localRole"]: f.append("local-role-confusion:"+bid)
        if rp.get("role")!=exp["remoteRole"]: f.append("remote-role-confusion:"+bid)
        if lp.get("rootAuthority") or rp.get("rootAuthority"): f.append("root-role-confusion:"+bid)
        le=em.get(b.get("localEndpointId"),{}); re=em.get(b.get("remoteEndpointId"),{})
        if (le.get("channelId"),le.get("side"),le.get("purpose"),le.get("expectedPrincipalId"))!=(exp["channelId"],"local",exp["localPurpose"],b.get("localPrincipalId")): f.append("local-endpoint-confusion:"+bid)
        if (re.get("channelId"),re.get("side"),re.get("purpose"),re.get("expectedPrincipalId"))!=(exp["channelId"],"remote",exp["remotePurpose"],b.get("remotePrincipalId")): f.append("remote-endpoint-confusion:"+bid)
        t=tm.get(b.get("transportProfileId"),{})
        if (t.get("channelId"),t.get("direction"),t.get("protocolFamily"))!=(exp["channelId"],exp["direction"],exp["protocol"]): f.append("transport-confusion:"+bid)
        s=sm.get(b.get("expectedPinsetId"),{})
        if s.get("endpointId")!=b.get("remoteEndpointId") or re.get("pinsetId")!=b.get("expectedPinsetId"): f.append("pinset-endpoint-confusion:"+bid)
        if b.get("contextCommitment")!=canon_sha({k:b.get(k) for k in CTX}): f.append("context-commitment:"+bid)
        if scope=="structural-only" and b.get("state")!="structural-only": f.append("structural-binding-state:"+bid)
        if scope=="operational" and b.get("state")!="operational": f.append("operational-binding-state:"+bid)
        for value,seen,code in [(b.get("localPrincipalId"),usedp,"cross-route-principal-reuse"),(b.get("remotePrincipalId"),usedp,"cross-route-principal-reuse"),(b.get("localEndpointId"),usede,"cross-route-endpoint-reuse"),(b.get("remoteEndpointId"),usede,"cross-route-endpoint-reuse"),(b.get("expectedPinsetId"),useds,"cross-route-pinset-reuse"),(b.get("transportProfileId"),usedt,"cross-route-transport-reuse")]:
            if value in seen: f.append(code+":"+str(value))
            seen.add(value)
    return sorted(set(f))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("registry"); ap.add_argument("--json",action="store_true"); ap.add_argument("--require-conformant",action="store_true")
    ns=ap.parse_args(); d=json.loads(Path(ns.registry).read_text(encoding="utf-8")); findings=validate(d)
    out={"standard":"EIGIIB-IDP-A2-0.1","result":"CONFORMANT" if not findings else "NON_CONFORMANT","findings":findings}
    print(json.dumps(out,sort_keys=True) if ns.json else out["result"]+("\n"+"\n".join(findings) if findings else ""))
    return 1 if ns.require_conformant and findings else 0
if __name__=="__main__": raise SystemExit(main())
