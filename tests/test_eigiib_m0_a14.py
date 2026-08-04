import json, shutil, tempfile, unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from eigiib_m0_a14_check import evaluate
from eigiib_m0_a14_replay import verify_case
A13_HEAD="d096b9fbf68cead15a3a9eb7bf4cff1493a0aa45"
H=lambda c: (c*64)[:64]
COLLEGES=("normative-authority-college","operational-governance-college","independent-verification-college")

def approvals(digest,prefix="a"):
    out=[]
    for ci,c in enumerate(COLLEGES):
        for i in range(4): out.append({"collegeId":c,"approverId":f"{prefix}-{ci}-{i}","controlDomainId":f"{prefix}-domain-{ci}-{i}","recordDigest":digest})
    return out

def snapshot(d="1",member_prefix="g",threshold=4,domains=5,unknown=False):
    return {"snapshotDigest":H(d),"unknownControlOverlap":unknown,"colleges":[{"id":c,"members":5,"threshold":threshold,"distinctControlDomains":domains,"memberIds":[f"{member_prefix}-{ci}-m{i}" for i in range(5)],"controlDomainIds":[f"{member_prefix}-{ci}-d{i}" for i in range(domains)]} for ci,c in enumerate(COLLEGES)]}

def cycle(seq, pred, succ, issued, executed, closed, snap, revoked=False):
    req=H(str(seq+2)); auth=H(str(seq+5))
    rev=[]
    writes=[{"path":f"conformance/c{seq}.json","at":issued.replace("00:00:00","01:00:00")}]
    if revoked:
        subset=[{"collegeId":COLLEGES[0],"approverId":f"r-{i}","controlDomainId":f"rd-{i}","recordDigest":req} for i in range(4)]
        rev=[{"revocationId":f"rev-{seq}","collegeId":COLLEGES[0],"requestDigest":req,"effectiveAt":issued.replace("00:00:00","02:00:00"),"approvals":subset,"outcome":"revoked-and-refrozen"}]
    return {"sequence":seq,"maintenanceEventId":f"event-{seq}","maintenanceClass":"normative-correction","predecessorRefreezeDigest":pred,"successorRefreezeDigest":succ,"requestDigest":req,"reopeningAuthorityDigest":auth,"issuedAt":issued,"expiresAt":issued.replace("00:00:00","23:00:00"),"executedAt":executed,"closedAt":closed,"affectedPaths":[f"conformance/c{seq}.json"],"implementedPaths":[f"conformance/c{seq}.json"],"approvals":approvals(req,f"c{seq}"),"governanceSnapshot":snap,"governanceTransition":None,"revocationEvents":rev,"authorizedWrites":writes,"supersessionRecordValid":True,"independentVerificationValid":True,"workflowConclusions":["success"]*3,"refreezeManifestValid":True,"independentRefreezeReadbackValid":True,"closureCertificateValid":True}

def complete_case():
    s=snapshot("a"); initial=H("0")
    c1=cycle(1,initial,H("1"),"2026-01-01T00:00:00Z","2026-01-01T03:00:00Z","2026-01-02T00:00:00Z",s,True)
    c2=cycle(2,H("1"),H("2"),"2026-01-15T00:00:00Z","2026-01-15T03:00:00Z","2026-01-16T00:00:00Z",s)
    c3=cycle(3,H("2"),H("3"),"2026-02-01T00:00:00Z","2026-02-01T03:00:00Z","2026-02-02T00:00:00Z",s)
    return {"a13Decision":"verified","a13Head":A13_HEAD,"a13ClosureCertificateValid":True,"initialRefreezeDigest":initial,"cycles":[c1,c2,c3],"continuityCertificateValid":True}

class M0A14Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.t=Path(self.tmp.name)
        freeze=json.loads((ROOT/"conformance/m0-a14-authority-freeze.json").read_text())
        for e in freeze["authorities"]:
            src=ROOT/e["path"]; dst=self.t/e["path"]; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
        p=self.t/"conformance/m0-a14-authority-freeze.json"; p.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/"conformance/m0-a14-authority-freeze.json",p)
    def tearDown(self): self.tmp.cleanup()
    def test_canonical_baseline(self): self.assertEqual(evaluate(self.t),json.loads((ROOT/"tests/fixtures/m0-a14/expected-baseline-report.json").read_text()))
    def test_require_state_is_not_t(self): self.assertEqual(evaluate(self.t)["htntLabel"],"NF")
    def test_complete_synthetic_chain(self): self.assertTrue(verify_case(complete_case())["verified"])
    def test_a13_required(self): c=complete_case(); c["a13Decision"]="not-verified"; self.assertIn("m0-a13-not-verified",verify_case(c)["errors"])
    def test_three_cycles_required(self): c=complete_case(); c["cycles"]=c["cycles"][:2]; self.assertIn("minimum-cycle-count-not-met",verify_case(c)["errors"])
    def test_sequence_gap(self): c=complete_case(); c["cycles"][1]["sequence"]=3; self.assertIn("cycle-sequence-gap",verify_case(c)["errors"])
    def test_refreeze_chain_break(self): c=complete_case(); c["cycles"][1]["predecessorRefreezeDigest"]=H("f"); self.assertIn("refreeze-chain-broken",verify_case(c)["errors"])
    def test_cycle_overlap(self): c=complete_case(); c["cycles"][1]["issuedAt"]="2026-01-01T12:00:00Z"; self.assertIn("cycle-overlap-or-nonmonotonic-time",verify_case(c)["errors"])
    def test_minimum_span(self): c=complete_case(); c["cycles"][2]["issuedAt"]="2026-01-20T00:00:00Z"; c["cycles"][2]["executedAt"]="2026-01-20T03:00:00Z"; c["cycles"][2]["expiresAt"]="2026-01-20T23:00:00Z"; c["cycles"][2]["closedAt"]="2026-01-21T00:00:00Z"; self.assertIn("minimum-observed-span-not-met",verify_case(c)["errors"])
    def test_revocation_required(self): c=complete_case(); c["cycles"][0]["revocationEvents"]=[]; self.assertIn("revocation-exercise-missing",verify_case(c)["errors"])
    def test_revocation_threshold(self): c=complete_case(); c["cycles"][0]["revocationEvents"][0]["approvals"]=c["cycles"][0]["revocationEvents"][0]["approvals"][:3]; self.assertIn("revocation-threshold-not-met",verify_case(c)["errors"])
    def test_post_revocation_write(self): c=complete_case(); c["cycles"][0]["authorizedWrites"].append({"path":"conformance/c1.json","at":"2026-01-01T04:00:00Z"}); self.assertIn("post-revocation-write-detected",verify_case(c)["errors"])
    def test_scope_wildcard(self): c=complete_case(); c["cycles"][0]["affectedPaths"]=["conformance/*.json"]; c["cycles"][0]["implementedPaths"]=["conformance/*.json"]; self.assertIn("cycle-1-scope-not-exact",verify_case(c)["errors"])
    def test_scope_expansion(self): c=complete_case(); c["cycles"][0]["implementedPaths"].append("extra"); self.assertIn("cycle-1-scope-expansion-or-omission",verify_case(c)["errors"])
    def test_college_threshold(self): c=complete_case(); c["cycles"][0]["approvals"]=c["cycles"][0]["approvals"][:-1]; self.assertTrue(any("threshold-not-met" in e for e in verify_case(c)["errors"]))
    def test_cross_college_identity_overlap(self): c=complete_case(); c["cycles"][0]["approvals"][4]["approverId"]=c["cycles"][0]["approvals"][0]["approverId"]; self.assertIn("cycle-1-cross-college-identity-overlap",verify_case(c)["errors"])
    def test_threshold_drift_rejected(self): c=complete_case(); c["cycles"][1]["governanceSnapshot"]=snapshot("b",threshold=3); c["cycles"][1]["governanceTransition"]={"fromSnapshotDigest":H("a"),"toSnapshotDigest":H("b"),"reasonCode":"rotation","effectiveAt":"2026-01-14T00:00:00Z","approvals":approvals(H("b"),"gt"),"independentReviewValid":True}; self.assertIn("cycle-2-threshold-weakened",verify_case(c)["errors"])
    def test_domain_collapse_rejected(self): c=complete_case(); c["cycles"][0]["governanceSnapshot"]=snapshot("a",domains=3); self.assertIn("cycle-1-control-domain-collapse",verify_case(c)["errors"])
    def test_unknown_overlap_rejected(self): c=complete_case(); c["cycles"][0]["governanceSnapshot"]["unknownControlOverlap"]=True; self.assertIn("cycle-1-unknown-control-overlap",verify_case(c)["errors"])
    def test_undeclared_drift(self): c=complete_case(); c["cycles"][1]["governanceSnapshot"]=snapshot("b","h"); self.assertIn("governance-drift-undeclared",verify_case(c)["errors"])
    def test_declared_nonweakening_drift(self): c=complete_case(); c["cycles"][1]["governanceSnapshot"]=snapshot("b","h"); c["cycles"][1]["governanceTransition"]={"fromSnapshotDigest":H("a"),"toSnapshotDigest":H("b"),"reasonCode":"registered-rotation","effectiveAt":"2026-01-14T00:00:00Z","approvals":approvals(H("b"),"gt"),"independentReviewValid":True}; c["cycles"][2]["governanceSnapshot"]=snapshot("b","h"); self.assertTrue(verify_case(c)["verified"])
    def test_transition_chain_mismatch(self): c=complete_case(); c["cycles"][1]["governanceSnapshot"]=snapshot("b","h"); c["cycles"][1]["governanceTransition"]={"fromSnapshotDigest":H("x"),"toSnapshotDigest":H("b"),"reasonCode":"rotation","effectiveAt":"2026-01-14T00:00:00Z","approvals":approvals(H("b"),"gt"),"independentReviewValid":True}; self.assertIn("governance-transition-chain-mismatch",verify_case(c)["errors"])
    def test_spurious_transition(self): c=complete_case(); c["cycles"][1]["governanceTransition"]={"fromSnapshotDigest":H("a"),"toSnapshotDigest":H("a"),"reasonCode":"none","effectiveAt":"2026-01-14T00:00:00Z","approvals":approvals(H("a"),"gt"),"independentReviewValid":True}; self.assertIn("spurious-governance-transition",verify_case(c)["errors"])
    def test_duplicate_event(self): c=complete_case(); c["cycles"][1]["maintenanceEventId"]="event-1"; self.assertIn("maintenance-event-id-not-unique",verify_case(c)["errors"])
    def test_reused_request_digest(self): c=complete_case(); c["cycles"][1]["requestDigest"]=c["cycles"][0]["requestDigest"]; c["cycles"][1]["approvals"]=approvals(c["cycles"][1]["requestDigest"],"z"); self.assertIn("request-digest-invalid-or-reused",verify_case(c)["errors"])
    def test_workflow_failure(self): c=complete_case(); c["cycles"][2]["workflowConclusions"]=["failure"]; self.assertIn("cycle-3-workflow-inventory-not-green",verify_case(c)["errors"])
    def test_certificate_required(self): c=complete_case(); c["continuityCertificateValid"]=False; self.assertIn("continuity-certificate-invalid",verify_case(c)["errors"])
    def test_premature_evidence_is_nt(self): p=self.t/"evidence/m0-a14/multi-cycle-chain.json"; p.parent.mkdir(parents=True); p.write_text(json.dumps(complete_case())); self.assertEqual(evaluate(self.t)["htntLabel"],"NT")
    def test_source_head_mutation_is_f(self): p=self.t/"conformance/m0-a14-continuity-authority.json"; d=json.loads(p.read_text()); d["source"]["m0A13Head"]="0"*40; p.write_text(json.dumps(d)); self.assertEqual(evaluate(self.t)["htntLabel"],"F")
    def test_authority_freeze_mutation_is_f(self): p=self.t/"conformance/m0-a14-revocation-policy.json"; p.write_text(p.read_text()+" "); self.assertEqual(evaluate(self.t)["htntLabel"],"F")

if __name__=="__main__": unittest.main()
