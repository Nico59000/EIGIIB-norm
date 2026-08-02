#!/usr/bin/env python3
"""EIGIIB E14-A4 static revocation, withdrawal and anti-rollback replay."""
from __future__ import annotations
import argparse,hashlib,json,tomllib
from dataclasses import asdict,dataclass
from pathlib import Path

V="0.1.0";STD="EIGIIB-E14-A4-1.0";A1="EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0+E14-1.0";A2="EIGIIB-E14-A2-1.0";A3="EIGIIB-E14-A3-1.0"
FINAL=("admissible","held","rejected","unavailable");NEG={"revoked","withdrawn","superseded","stale","rollback-detected","deny","rejected"}
@dataclass(order=True)
class F:severity:str;code:str;path:str;message:str
class Checker:
 def __init__(self,root:Path,registry=Path("conformance/disclosure-revocation.json"),projection_registry=Path("conformance/confidential-evidence.json"),authorization_registry=Path("conformance/disclosure-authorization.json"),correlation_registry=Path("conformance/correlation-control.json")):
  self.root=root.resolve();self.rp=Path(registry);self.p1=Path(projection_registry);self.p2=Path(authorization_registry);self.p3=Path(correlation_registry);self.fs=[];self.d={};self.o={};self.rec={};self.proj={};self.ar={};self.ad={};self.er={};self.co={};self.fr={};self.ch={};self.h={};self.at={};self.de={};self.latest={};self.good=set();self.derived={}
 @staticmethod
 def ne(x):return isinstance(x,str) and bool(x)
 @staticmethod
 def ni(x,n=0):return isinstance(x,int) and not isinstance(x,bool) and x>=n
 @staticmethod
 def canonical_digest(x):return hashlib.sha256((json.dumps({k:v for k,v in x.items() if k!="commitment"},sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()).hexdigest()
 def add(self,c,m,p=""):self.fs.append(F("error",c,p,m))
 def bad(self,p):return any(f.path==p or f.path.startswith(p+".") for f in self.fs)
 def path(self,r,c,must=True):
  if not self.ne(str(r)) or Path(r).is_absolute():self.add(c+".PATH","path must be repository-relative",str(r));return None
  p=(self.root/r).resolve(strict=False)
  try:p.relative_to(self.root)
  except ValueError:self.add(c+".PATH","path escapes repository",str(r));return None
  if must and not p.is_file():self.add(c+".MISSING","file is missing",str(r));return None
  return p
 def load(self,r,c):
  p=self.path(r,c)
  if not p:return None
  try:x=json.loads(p.read_text(),parse_constant=lambda z:(_ for _ in()).throw(ValueError(z)))
  except Exception as e:self.add(c+".PARSE",str(e),str(r));return None
  if not isinstance(x,dict):self.add(c+".TYPE","root must be object",str(r));return None
  return x
 def ix(self,x,k,c):
  a=x.get(k);out={}
  if not isinstance(a,list):self.add(c+".TYPE",k+" must be array",k);return out
  for i,v in enumerate(a):
   p=f"{k}[{i}]";z=v.get("id") if isinstance(v,dict) else None
   if not self.ne(z) or z in out:self.add(c+".ID","invalid or duplicate id",p)
   else:out[z]=v
  return out
 def commit(self,x,p,c):
  q=x.get("commitment");d=q.get("digest") if isinstance(q,dict) and q.get("algorithm")=="sha256" else None
  if not self.ne(d) or d!=self.canonical_digest(x):self.add(c+".COMMITMENT","canonical sha256 commitment mismatch",p)
  return d
 def profile(self):
  try:x=tomllib.loads((self.root/"EIGIIB.toml").read_text())
  except Exception as e:self.add("E14A4.PROFILE.PARSE",str(e),"EIGIIB.toml");return
  if "E14-1.0" not in x.get("extensions",[]) or x.get("revision")!="EIGIIB-E14-draft-1.0":self.add("E14A4.PROFILE.ADOPTION","E14 adoption/revision mismatch","EIGIIB.toml")
  e={"confidential_evidence":"conformance/confidential-evidence.json","disclosure_authorization":"conformance/disclosure-authorization.json","correlation_control":"conformance/correlation-control.json","e14_a4_contract":"extensions/E14-A4-REVOCATION-FRESHNESS-DISTRIBUTION-WITHDRAWAL-DISCLOSURE-ANTI-ROLLBACK-REPLAY.md","disclosure_revocation":"conformance/disclosure-revocation.json","e14_a4_human_mastery":"docs/E14-A4-HUMAN-MASTERY-GUIDE.md"};a=x.get("authorities",{});r=x.get("required_authorities",[])
  for k,v in e.items():
   if a.get(k)!=v or k not in r:self.add("E14A4.PROFILE.AUTHORITY",k+" authority missing","EIGIIB.toml")
   else:self.path(Path(v),"E14A4.PROFILE")
  g=[z for z in x.get("manual_gates",[]) if isinstance(z,dict) and z.get("id")=="e14-a4-revocation-freshness-boundary-review"]
  if len(g)!=1 or (g[0].get("status"),g[0].get("authority"),g[0].get("attestation"))!=("complete","e14_a4_contract","conformance/E14-A4-MANUAL-REVIEW.md"):self.add("E14A4.PROFILE.GATE","manual gate mismatch","EIGIIB.toml")
 def upstream(self,a,b,c):
  if a.get("standard")!=A1:self.add("E14A4.A1.STANDARD","bad A1 standard",str(self.p1))
  if b.get("standard")!=A2:self.add("E14A4.A2.STANDARD","bad A2 standard",str(self.p2))
  if c.get("standard")!=A3:self.add("E14A4.A3.STANDARD","bad A3 standard",str(self.p3))
  self.rec=self.ix(a,"records","E14A4.A1.RECORD");self.proj=self.ix(a,"projections","E14A4.A1.PROJECTION");self.ar=self.ix(b,"requests","E14A4.A2.REQUEST");self.ad=self.ix(b,"decisions","E14A4.A2.DECISION");self.er=self.ix(c,"enforcement_requests","E14A4.A3.REQUEST");self.co=self.ix(c,"consumptions","E14A4.A3.CONSUMPTION")
 def objects(self):
  for i,x in self.fr.items():
   if not self.ne(x.get("revision")) or x.get("state") not in {"active","revoked","contested","unavailable"} or not self.ni(x.get("current_epoch")):self.add("E14A4.FRESHNESS","invalid freshness source","freshness:"+i)
  for i,x in self.ch.items():
   p="distribution:"+i;q=self.proj.get(x.get("projection"))
   if x.get("state") not in {"active","withdrawn","contested","unavailable"} or not q or x.get("projection_revision")!=q.get("revision") or x.get("projection_commitment")!=q.get("commitment",{}).get("digest"):self.add("E14A4.DISTRIBUTION","invalid distribution binding",p)
   self.commit(x,p,"E14A4.DISTRIBUTION")
  groups={}
  for i,x in self.h.items():
   p="history:"+i;k=x.get("subject_kind");obj=self.rec.get(x.get("subject")) if k=="source-record" else self.proj.get(x.get("subject")) if k=="projection" else self.ch.get(x.get("subject")) if k=="distribution" else None;au=self.fr.get(x.get("authority"))
   if not obj or not au or x.get("authority_revision")!=au.get("revision") or x.get("subject_revision")!=obj.get("revision") or x.get("subject_commitment")!=obj.get("commitment",{}).get("digest") or x.get("state") not in {"active","revoked","withdrawn","superseded","unavailable"} or not self.ni(x.get("generation"),1) or not self.ni(x.get("observed_epoch")) or not self.ni(x.get("valid_until_epoch")) or x.get("valid_until_epoch",-1)<x.get("observed_epoch",0):self.add("E14A4.HISTORY","invalid history entry",p)
   self.commit(x,p,"E14A4.HISTORY");key=(k,x.get("subject"),x.get("subject_revision"),x.get("subject_commitment"),x.get("authority"),x.get("authority_revision"));groups.setdefault(key,[]).append(x)
  for key,a in groups.items():
   a.sort(key=lambda z:z.get("generation",0))
   if [z.get("generation") for z in a]!=list(range(1,len(a)+1)):self.add("E14A4.HISTORY.GENERATION_GAP","non-contiguous generations","history-chain:"+str(key[:2]))
   for n,z in enumerate(a):
    want=None if n==0 else {"id":a[n-1].get("id"),"commitment":a[n-1].get("commitment",{}).get("digest")}
    if z.get("predecessor")!=want:self.add("E14A4.HISTORY.PREDECESSOR","predecessor mismatch","history:"+z.get("id",""))
   if a:self.latest[key]=a[-1]
 def head(self,r,k,o,a,e,p):
  h=self.h.get(r.get("id")) if isinstance(r,dict) else None
  if not h or r.get("commitment")!=h.get("commitment",{}).get("digest") or not self.ni(r.get("minimum_generation"),1):self.add("E14A4.ATTEMPT.HEAD","invalid head reference",p);return "unavailable","unavailable","unavailable"
  key=(k,o.get("id"),o.get("revision"),o.get("commitment",{}).get("digest"),a.get("id"),a.get("revision"));latest=self.latest.get(key)
  if h.get("subject_kind")!=k or h.get("subject")!=o.get("id") or h.get("authority")!=a.get("id"):self.add("E14A4.ATTEMPT.HEAD_BINDING","head binding mismatch",p)
  rb="current" if latest and latest.get("id")==h.get("id") and h.get("generation",0)>=r.get("minimum_generation",1) else "rollback-detected";fr="not-yet-effective" if e<h.get("observed_epoch",0) else "stale" if e>h.get("valid_until_epoch",-1) else "fresh"
  if a.get("state")=="unavailable":return "unavailable","unavailable","unavailable"
  if a.get("state") in {"contested","revoked"}:return "held","held","held"
  return h.get("state"),fr,rb
 def attempts(self):
  for i,x in self.at.items():
   p="attempt:"+i;r=self.rec.get(x.get("source_record"));q=self.proj.get(x.get("projection"));ar=self.ar.get(x.get("authorization_request"));ad=self.ad.get(x.get("authorization_decision"));er=self.er.get(x.get("enforcement_request"));co=self.co.get(x.get("correlation_consumption"));ch=self.ch.get(x.get("distribution"));fr=self.fr.get(x.get("freshness_source"))
   ok=all((r,q,ar,ad,er,co,ch,fr)) and x.get("source_revision")==r.get("revision") and x.get("source_commitment")==r.get("commitment",{}).get("digest") and x.get("projection_revision")==q.get("revision") and x.get("projection_commitment")==q.get("commitment",{}).get("digest") and q.get("source_record")==r.get("id") and x.get("authorization_request_revision")==ar.get("revision") and ar.get("projection")==q.get("id") and x.get("authorization_decision_request_revision")==ad.get("request_revision") and ad.get("request")==ar.get("id") and x.get("enforcement_request_revision")==er.get("revision") and er.get("authorization_decision")==ad.get("id") and x.get("correlation_consumption_revision")==co.get("revision") and co.get("enforcement_request")==er.get("id") and x.get("distribution_revision")==ch.get("revision") and x.get("distribution_commitment")==ch.get("commitment",{}).get("digest") and ch.get("projection")==q.get("id") and x.get("freshness_source_revision")==fr.get("revision") and x.get("evaluation_epoch")==fr.get("current_epoch")
   if not ok:self.add("E14A4.ATTEMPT.BINDING","exact upstream binding mismatch",p)
   else:self.good.add(i)
 def components(self,x):
  r=self.rec[x["source_record"]];q=self.proj[x["projection"]];ch=self.ch[x["distribution"]];a=self.fr[x["freshness_source"]];e=x["evaluation_epoch"];sr,sf,sb=self.head(x["source_head"],"source-record",r,a,e,"attempt:"+x["id"]+".source");pr,pf,pb=self.head(x["projection_head"],"projection",q,a,e,"attempt:"+x["id"]+".projection");dr,df,db=self.head(x["distribution_head"],"distribution",ch,a,e,"attempt:"+x["id"]+".distribution")
  if ch.get("state")=="withdrawn":dr="withdrawn"
  elif ch.get("state")=="contested" and dr=="active":dr="held"
  elif ch.get("state")=="unavailable" and dr=="active":dr="unavailable"
  dist={"active":"available","revoked":"withdrawn","withdrawn":"withdrawn","superseded":"superseded","held":"held","unavailable":"unavailable"}.get(dr,"unavailable");f="stale" if "stale" in {sf,pf,df} else "unavailable" if "unavailable" in {sf,pf,df} else "held" if "held" in {sf,pf,df} else "not-yet-effective" if "not-yet-effective" in {sf,pf,df} else "fresh";rb="rollback-detected" if "rollback-detected" in {sb,pb,db} else "unavailable" if "unavailable" in {sb,pb,db} else "held" if "held" in {sb,pb,db} else "current"
  return {"source_status_result":sr,"projection_status_result":pr,"distribution_status_result":dist,"freshness_result":f,"rollback_result":rb,"authorization_result":self.ad[x["authorization_decision"]].get("state"),"correlation_result":self.co[x["correlation_consumption"]].get("state")}
 def decisions(self):
  seen={}
  for i,x in self.de.items():
   p="decision:"+i;a=self.at.get(x.get("attempt"));seen[x.get("attempt")]=seen.get(x.get("attempt"),0)+1
   if not a or a.get("id") not in self.good or x.get("attempt_revision")!=a.get("revision"):self.add("E14A4.DECISION.ATTEMPT","invalid attempt",p);continue
   z=self.components(a);state="rejected" if any(v in NEG for v in z.values()) else "unavailable" if "unavailable" in z.values() else "held" if any(v in {"held","not-yet-effective"} for v in z.values()) else "admissible"
   if any(x.get(k)!=v for k,v in z.items()) or x.get("state")!=state:self.add("E14A4.DECISION.DERIVATION","derived decision mismatch",p)
   if state in {"admissible","rejected"} and not x.get("evidence"):self.add("E14A4.DECISION.EVIDENCE","material evidence required",p)
   self.derived[i]={**z,"state":state}
  for a,n in seen.items():
   if n>1:self.add("E14A4.DECISION.DUPLICATE","duplicate decision","attempt:"+str(a))
 def run(self):
  self.profile();a=self.load(self.p1,"E14A4.A1");b=self.load(self.p2,"E14A4.A2");c=self.load(self.p3,"E14A4.A3");r=self.load(self.rp,"E14A4.REGISTRY")
  if a and b and c:self.upstream(a,b,c)
  if r:
   if r.get("standard")!=STD or r.get("status")!="structural-only" or r.get("upstream_projection_registry")!=str(self.p1) or r.get("upstream_authorization_registry")!=str(self.p2) or r.get("upstream_correlation_registry")!=str(self.p3):self.add("E14A4.REGISTRY","registry envelope mismatch",str(self.rp))
   self.fr=self.ix(r,"freshness_sources","E14A4.FRESHNESS");self.ch=self.ix(r,"distribution_channels","E14A4.DISTRIBUTION");self.h=self.ix(r,"status_histories","E14A4.HISTORY");self.at=self.ix(r,"disclosure_attempts","E14A4.ATTEMPT");self.de=self.ix(r,"decisions","E14A4.DECISION")
   if a and b and c:self.objects();self.attempts();self.decisions()
  bad=bool(self.fs);ev="not-evaluated" if not self.de else "non-conformant" if bad else "conformant";states=[v.get("state") for v in self.derived.values()]
  return {"tool":"eigiib-disclosure-revocation-check","tool_version":V,"standard":STD,"structural_result":"non-conformant" if bad else "conformant","upstream_binding_result":"non-conformant" if any(f.code.startswith(("E14A4.A1","E14A4.A2","E14A4.A3")) for f in self.fs) else "conformant","revocation_freshness_result":ev,"distribution_withdrawal_result":ev,"anti_rollback_result":ev,"freshness_source_count":len(self.fr),"distribution_channel_count":len(self.ch),"status_history_count":len(self.h),"disclosure_attempt_count":len(self.at),"decision_count":len(self.de),"decision_counts":{s:states.count(s) for s in FINAL},"findings":[asdict(f) for f in sorted(self.fs)]}
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--registry",default="conformance/disclosure-revocation.json");p.add_argument("--projection-registry",default="conformance/confidential-evidence.json");p.add_argument("--authorization-registry",default="conformance/disclosure-authorization.json");p.add_argument("--correlation-registry",default="conformance/correlation-control.json");p.add_argument("--json",action="store_true");a=p.parse_args(argv);r=Checker(Path(a.root),Path(a.registry),Path(a.projection_registry),Path(a.authorization_registry),Path(a.correlation_registry)).run();print(json.dumps(r,indent=2,sort_keys=True));return r["structural_result"]!="conformant"
if __name__=="__main__":raise SystemExit(main())
