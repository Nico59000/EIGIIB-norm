#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

HEX=re.compile(r"^[0-9a-f]{64}$")
SOURCE=("ec352636690ee22135cfc7a3d3e2067ee323f2cf","conformance/idp-policy.json","7aac9aa7223eadd3739c0b59d4275eeed58bb3d1")
ROUTES={
 "bridge-out-binding":("private-bridge-out","outbound","bridge-origin","bridge-peer","origin","peer","ssh",("D0","D1","D2","D3")),
 "bridge-return-binding":("private-bridge-return","inbound","bridge-return-receiver","bridge-return-peer","receiver","peer","ssh",("D0","D1","D2","D3")),
 "restricted-review-binding":("restricted-review","bidirectional","restricted-review-origin","restricted-review-peer","origin","peer","tls",("D4",))
}
CTX=("channelId","direction","localPrincipalId","remotePrincipalId","localEndpointId","remoteEndpointId","transportProfileId","expectedPinsetId","allowedClasses")

def digest(x):
    return hashlib.sha256((json.dumps(x,sort_keys=True,separators=(",",":"))+"\n").encode()).hexdigest()

def index(xs):
    if not isinstance(xs,list): return {},False
    m={}
    for x in xs:
        if not isinstance(x,dict) or not isinstance(x.get("id"),str) or x["id"] in m: return m,False
        m[x["id"]]=x
    return m,True

def validate(d):
    bad=[]
    def no(code): bad.append(code)
    if d.get("standard")!="EIGIIB-IDP-A2-0.1": no("standard")
    s=d.get("sourceA1",{})
    if (s.get("head"),s.get("policyPath"),s.get("policyBlobSha"))!=SOURCE: no("source-a1-binding")
    scope=d.get("registryScope")
    if scope not in ("structural-only","operational"): no("registry-scope")
    if len(d.get("rules",{}))!=15 or not all(v is True for v in d.get("rules",{}).values()): no("rules")
    p,pok=index(d.get("principals")); e,eok=index(d.get("endpoints")); q,qok=index(d.get("pinsets")); t,tok=index(d.get("transportProfiles")); b,bok=index(d.get("bindings"))
    if not all((pok,eok,qok,tok,bok)): no("duplicate-or-shape")
    roots=[x["id"] for x in d.get("principals",[]) if isinstance(x,dict) and x.get("rootAuthority") is True]
    if roots!=["l0-local-authority"] or p.get("l0-local-authority",{}).get("role")!="local-root": no("root-authority-principal")
    dom=set(); key=set(); fpr=set()
    for pid,x in p.items():
        if pid!="l0-local-authority" and x.get("rootAuthority") is not False: no("bridge-root-authority:"+pid)
        a=x.get("authenticator",{})
        if a.get("kind")!="asymmetric-key" or a.get("fingerprintAlgorithm")!="sha256" or not HEX.fullmatch(str(a.get("publicKeyFingerprint",""))): no("authenticator:"+pid)
        for v,seen,label in ((x.get("controlDomainId"),dom,"domain"),(a.get("keyId"),key,"key"),(a.get("publicKeyFingerprint"),fpr,"fingerprint")):
            if v in seen: no(label+"-reuse:"+pid)
            seen.add(v)
        if scope=="structural-only" and (a.get("synthetic") is not True or x.get("operationalState")!="planned"): no("structural-principal:"+pid)
        if scope=="operational" and a.get("synthetic") is not False: no("operational-principal:"+pid)
    for eid,x in e.items():
        if x.get("expectedPrincipalId") not in p: no("endpoint-principal:"+eid)
        if scope=="structural-only" and (x.get("locatorState")!="unbound" or x.get("locator") is not None or x.get("operationalState")!="planned"): no("structural-endpoint:"+eid)
        if scope=="operational" and (x.get("locatorState")!="bound" or not x.get("locator")): no("operational-endpoint:"+eid)
    for qid,x in q.items():
        pins=x.get("pins",[])
        if x.get("algorithm")!="sha256" or not pins or any(not HEX.fullmatch(str(v)) for v in pins): no("pinset:"+qid)
        body={k:x.get(k) for k in ("id","endpointId","algorithm","pins","synthetic")}
        if x.get("commitment")!=digest(body): no("pinset-commitment:"+qid)
        if scope=="structural-only" and x.get("synthetic") is not True: no("structural-pinset:"+qid)
        if scope=="operational" and x.get("synthetic") is not False: no("operational-pinset:"+qid)
    if set(b)!=set(ROUTES): no("binding-set")
    seenp=set(); seene=set(); seenq=set(); seent=set()
    for bid,exp in ROUTES.items():
        x=b.get(bid,{})
        ch,dr,lr,rr,lp,rp,proto,classes=exp
        if (x.get("channelId"),x.get("direction"),tuple(x.get("allowedClasses",[])))!=(ch,dr,classes): no("route-envelope:"+bid)
        if "D5" in x.get("allowedClasses",[]): no("d5-bridge-forbidden:"+bid)
        pl=p.get(x.get("localPrincipalId"),{}); pr=p.get(x.get("remotePrincipalId"),{})
        if pl.get("role")!=lr: no("local-role-confusion:"+bid)
        if pr.get("role")!=rr: no("remote-role-confusion:"+bid)
        if pl.get("rootAuthority") or pr.get("rootAuthority"): no("root-role-confusion:"+bid)
        el=e.get(x.get("localEndpointId"),{}); er=e.get(x.get("remoteEndpointId"),{})
        if (el.get("channelId"),el.get("side"),el.get("purpose"),el.get("expectedPrincipalId"))!=(ch,"local",lp,x.get("localPrincipalId")): no("local-endpoint-confusion:"+bid)
        if (er.get("channelId"),er.get("side"),er.get("purpose"),er.get("expectedPrincipalId"))!=(ch,"remote",rp,x.get("remotePrincipalId")): no("remote-endpoint-confusion:"+bid)
        tr=t.get(x.get("transportProfileId"),{})
        if (tr.get("channelId"),tr.get("direction"),tr.get("protocolFamily"))!=(ch,dr,proto): no("transport-confusion:"+bid)
        if tr and (tr.get("peerAuthentication")!="mutual-asymmetric" or not all(tr.get(z) is True for z in ("confidentialityRequired","integrityRequired","endpointPinningRequired","channelBindingRequired"))): no("transport-policy:"+bid)
        ps=q.get(x.get("expectedPinsetId"),{})
        if ps.get("endpointId")!=x.get("remoteEndpointId") or er.get("pinsetId")!=x.get("expectedPinsetId"): no("pinset-endpoint-confusion:"+bid)
        if x.get("contextCommitment")!=digest({k:x.get(k) for k in CTX}): no("context-commitment:"+bid)
        if scope=="structural-only" and (x.get("state")!="structural-only" or tr.get("operationalState")!="planned"): no("structural-binding:"+bid)
        if scope=="operational" and x.get("state")!="operational": no("operational-binding:"+bid)
        for v,seen,label in ((x.get("localPrincipalId"),seenp,"principal"),(x.get("remotePrincipalId"),seenp,"principal"),(x.get("localEndpointId"),seene,"endpoint"),(x.get("remoteEndpointId"),seene,"endpoint"),(x.get("expectedPinsetId"),seenq,"pinset"),(x.get("transportProfileId"),seent,"transport")):
            if v in seen: no("cross-route-"+label+"-reuse:"+str(v))
            seen.add(v)
    return sorted(set(bad))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("registry"); ap.add_argument("--json",action="store_true"); ap.add_argument("--require-conformant",action="store_true")
    ns=ap.parse_args(); d=json.loads(Path(ns.registry).read_text(encoding="utf-8")); f=validate(d)
    out={"standard":"EIGIIB-IDP-A2-0.1","result":"CONFORMANT" if not f else "NON_CONFORMANT","findings":f}
    print(json.dumps(out,sort_keys=True) if ns.json else out["result"]+("\n"+"\n".join(f) if f else ""))
    return 1 if ns.require_conformant and f else 0
if __name__=="__main__": raise SystemExit(main())
