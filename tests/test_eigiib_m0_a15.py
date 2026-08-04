import json, shutil, tempfile, unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from eigiib_m0_a15_check import evaluate
from eigiib_m0_a15_replay import verify_case

A14_HEAD="5936ed072187cd7fe72db2c33119c8db92d06570"
REGISTRIES=("maintenance-registry-alpha","maintenance-registry-beta","maintenance-registry-gamma")

def h(n): return f"{n:064x}"[-64:]

class M0A15Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.t=Path(self.tmp.name)
        freeze=json.loads((ROOT/"conformance/m0-a15-authority-freeze.json").read_text())
        for entry in freeze["authorities"]:
            src=ROOT/entry["path"]; dst=self.t/entry["path"]; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
        dst=self.t/"conformance/m0-a15-authority-freeze.json"; dst.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/"conformance/m0-a15-authority-freeze.json",dst)
        a14=self.t/"conformance/m0-a14-maintenance-ledger.json"; a14.write_text(json.dumps({"continuityDecision":"not-accumulated","driftDecision":"not-evaluated"}))
    def tearDown(self): self.tmp.cleanup()

    def case(self):
        regs=[]
        for i,rid in enumerate(REGISTRIES,1):
            regs.append({"registryId":rid,"providerOperator":f"provider-{i}","tenantAccount":f"tenant-{i}",
            "identityRoot":f"registry-root-{i}","privilegedAdministrator":f"admin-{i}",
            "storageDomain":f"storage-{i}","auditCustody":f"audit-{i}"})
        witnesses=[{"witnessId":f"witness-{i}","controlDomainId":f"w-domain-{i}","identityRoot":f"w-root-{i}"} for i in range(1,6)]
        start=datetime(2026,1,1,tzinfo=timezone.utc)
        prev_cp=None; prev_tip=None; prev_receipts={r:None for r in REGISTRIES}
        cps=[]
        for seq in range(1,7):
            cp_digest=h(100+seq); tip=h(200+seq); gov=h(300)
            receipts=[]
            for j,rid in enumerate(REGISTRIES,1):
                rd=h(1000+seq*10+j)
                receipts.append({"registryId":rid,"sequence":seq,"observedAt":(start+timedelta(days=(seq-1)*18)).isoformat(),
                "checkpointDigest":cp_digest,"cycleTipDigest":tip,"governanceSnapshotDigest":gov,
                "previousReceiptDigest":prev_receipts[rid],"receiptDigest":rd,"status":"authoritative"})
                prev_receipts[rid]=rd
            endorsements=[{"witnessId":f"witness-{i}","controlDomainId":f"w-domain-{i}","recordDigest":cp_digest,
                           "signedAt":(start+timedelta(days=(seq-1)*18,minutes=i)).isoformat()} for i in range(1,5)]
            cp={"sequence":seq,"observedAt":(start+timedelta(days=(seq-1)*18)).isoformat(),
                "previousCheckpointDigest":prev_cp,"previousCycleTipDigest":prev_tip,
                "checkpointDigest":cp_digest,"cycleTipDigest":tip,"governanceSnapshotDigest":gov,
                "registryReceipts":receipts,"witnessEndorsements":endorsements,
                "splitBrainEvents":[],"reconciliationRecord":None,"governanceReconciliation":None}
            if seq==3:
                event={"eventId":"split-1","sequence":seq,"checkpointDigest":cp_digest,
                       "conflictingHeads":[tip,h(999)],"detectionDecision":"freeze-and-quarantine"}
                rec_digest=h(5000)
                rec_end=[{"witnessId":f"witness-{i}","controlDomainId":f"w-domain-{i}","recordDigest":rec_digest,
                          "signedAt":(start+timedelta(days=36,hours=1,minutes=i)).isoformat()} for i in range(1,5)]
                cp["splitBrainEvents"]=[event]
                cp["reconciliationRecord"]={"recordDigest":rec_digest,"eventIds":["split-1"],
                    "commonAncestorDigest":h(198),"candidateHeads":[tip,h(999)],"authoritativeHead":tip,
                    "supportingRegistryIds":[REGISTRIES[0],REGISTRIES[1]],"quarantinedRegistryIds":[REGISTRIES[2]],
                    "witnessEndorsements":rec_end,"appendOnly":True,"staleHeadsRejected":True,
                    "quarantinedRegistryReadbackValid":True,"independentPublishedReadbackValid":True,
                    "governanceReconciliationValid":True}
            cps.append(cp); prev_cp=cp_digest; prev_tip=tip
        return {"a14Decision":"verified","a14Head":A14_HEAD,"a14ContinuityCertificateValid":True,
                "registries":regs,"witnesses":witnesses,"checkpoints":cps,
                "longTermReconciliationCertificateValid":True,"independentManualReadbackValid":True}

    def write_evidence(self,case):
        p=self.t/"evidence/m0-a15/reconciliation-history.json"; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(case))

    def test_baseline_nf(self): self.assertEqual(evaluate(self.t)["htntLabel"],"NF")
    def test_positive_replay(self): self.assertTrue(verify_case(self.case())["verified"])
    def test_positive_repository_t(self):
        (self.t/"conformance/m0-a14-maintenance-ledger.json").write_text(json.dumps({"continuityDecision":"accumulated","driftDecision":"controlled"}))
        self.write_evidence(self.case()); self.assertEqual(evaluate(self.t)["htntLabel"],"T")
    def test_premature_evidence_nt(self): self.write_evidence(self.case()); self.assertEqual(evaluate(self.t)["htntLabel"],"NT")
    def test_source_head_mutation_f(self):
        p=self.t/"conformance/m0-a15-witnessing-authority.json"; d=json.loads(p.read_text()); d["source"]["m0A14Head"]="0"*40; p.write_text(json.dumps(d))
        self.assertEqual(evaluate(self.t)["htntLabel"],"F")
    def test_freeze_mutation_f(self):
        p=self.t/"conformance/m0-a15-registry-policy.json"; p.write_text(p.read_text()+" ")
        self.assertEqual(evaluate(self.t)["htntLabel"],"F")
    def test_a14_missing(self): c=self.case(); c["a14Decision"]="not-verified"; self.assertIn("m0-a14-not-verified",verify_case(c)["errors"])
    def test_checkpoint_count(self): c=self.case(); c["checkpoints"]=c["checkpoints"][:5]; self.assertIn("minimum-checkpoint-count-not-met",verify_case(c)["errors"])
    def test_observed_span(self):
        c=self.case()
        base=datetime(2026,1,1,tzinfo=timezone.utc)
        for i,x in enumerate(c["checkpoints"]): x["observedAt"]=(base+timedelta(days=i)).isoformat()
        self.assertIn("minimum-observed-span-not-met",verify_case(c)["errors"])
    def test_sequence_gap(self): c=self.case(); c["checkpoints"][2]["sequence"]=4; self.assertIn("checkpoint-sequence-gap",verify_case(c)["errors"])
    def test_checkpoint_chain(self): c=self.case(); c["checkpoints"][2]["previousCheckpointDigest"]=h(9999); self.assertIn("checkpoint-chain-broken",verify_case(c)["errors"])
    def test_tip_chain(self): c=self.case(); c["checkpoints"][2]["previousCycleTipDigest"]=h(9999); self.assertIn("cycle-tip-history-chain-broken",verify_case(c)["errors"])
    def test_registry_missing(self): c=self.case(); c["checkpoints"][0]["registryReceipts"].pop(); self.assertIn("checkpoint-1-registry-receipts-incomplete",verify_case(c)["errors"])
    def test_registry_provider_overlap(self): c=self.case(); c["registries"][1]["providerOperator"]=c["registries"][0]["providerOperator"]; self.assertIn("registry-independence-providerOperator-invalid",verify_case(c)["errors"])
    def test_witness_quorum(self): c=self.case(); c["checkpoints"][0]["witnessEndorsements"]=c["checkpoints"][0]["witnessEndorsements"][:3]; self.assertIn("checkpoint-1-witness-quorum-not-met",verify_case(c)["errors"])
    def test_witness_domain_overlap(self): c=self.case(); c["witnesses"][1]["controlDomainId"]=c["witnesses"][0]["controlDomainId"]; self.assertIn("witness-control-domains-not-independent",verify_case(c)["errors"])
    def test_witness_registry_overlap(self): c=self.case(); c["witnesses"][0]["identityRoot"]=c["registries"][0]["identityRoot"]; self.assertIn("witness-registry-identity-overlap",verify_case(c)["errors"])
    def test_receipt_chain(self): c=self.case(); c["checkpoints"][1]["registryReceipts"][0]["previousReceiptDigest"]=h(77); self.assertIn("checkpoint-2-registry-receipt-chain-broken",verify_case(c)["errors"])
    def test_receipt_state_divergence(self): c=self.case(); c["checkpoints"][1]["registryReceipts"][0]["cycleTipDigest"]=h(77); self.assertIn("checkpoint-2-cross-registry-state-divergence",verify_case(c)["errors"])
    def test_receipt_binding(self): c=self.case(); c["checkpoints"][1]["registryReceipts"][0]["checkpointDigest"]=h(77); self.assertIn("checkpoint-2-registry-receipt-binding-mismatch",verify_case(c)["errors"])
    def test_split_brain_missing(self):
        c=self.case(); c["checkpoints"][2]["splitBrainEvents"]=[]; c["checkpoints"][2]["reconciliationRecord"]=None
        self.assertIn("split-brain-exercise-missing",verify_case(c)["errors"])
    def test_split_brain_unresolved(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]=None; self.assertIn("split-brain-unresolved",verify_case(c)["errors"])
    def test_registry_support(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]["supportingRegistryIds"]=[REGISTRIES[0]]; self.assertIn("reconciliation-registry-support-insufficient",verify_case(c)["errors"])
    def test_quarantine_missing(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]["quarantinedRegistryIds"]=[]; self.assertIn("reconciliation-quarantine-invalid",verify_case(c)["errors"])
    def test_stale_head_accepted(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]["staleHeadsRejected"]=False; self.assertIn("reconciliation-anti-rollback-invalid",verify_case(c)["errors"])
    def test_append_only_false(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]["appendOnly"]=False; self.assertIn("reconciliation-anti-rollback-invalid",verify_case(c)["errors"])
    def test_reconciliation_readback(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]["independentPublishedReadbackValid"]=False; self.assertIn("reconciliation-readback-missing",verify_case(c)["errors"])
    def test_authoritative_head(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]["authoritativeHead"]=h(999); self.assertIn("reconciliation-authoritative-head-mismatch",verify_case(c)["errors"])
    def test_reconciliation_witness_quorum(self): c=self.case(); c["checkpoints"][2]["reconciliationRecord"]["witnessEndorsements"]=c["checkpoints"][2]["reconciliationRecord"]["witnessEndorsements"][:3]; self.assertIn("reconciliation-witness-quorum-not-met",verify_case(c)["errors"])
    def test_governance_change_unreconciled(self): c=self.case(); c["checkpoints"][4]["governanceSnapshotDigest"]=h(301); [r.update({"governanceSnapshotDigest":h(301)}) for r in c["checkpoints"][4]["registryReceipts"]]; self.assertIn("governance-change-unreconciled",verify_case(c)["errors"])
    def test_governance_weakening(self):
        c=self.case(); cp=c["checkpoints"][4]; cp["governanceSnapshotDigest"]=h(301); [r.update({"governanceSnapshotDigest":h(301)}) for r in cp["registryReceipts"]]
        cp["governanceReconciliation"]={"fromSnapshotDigest":h(300),"toSnapshotDigest":h(301),"nonWeakening":False,"threeCollegeIdenticalApproval":True,"independentReviewValid":True,"effectiveAt":cp["observedAt"]}
        self.assertIn("governance-reconciliation-weakening",verify_case(c)["errors"])
    def test_governance_review(self):
        c=self.case(); cp=c["checkpoints"][4]; cp["governanceSnapshotDigest"]=h(301); [r.update({"governanceSnapshotDigest":h(301)}) for r in cp["registryReceipts"]]
        cp["governanceReconciliation"]={"fromSnapshotDigest":h(300),"toSnapshotDigest":h(301),"nonWeakening":True,"threeCollegeIdenticalApproval":True,"independentReviewValid":False,"effectiveAt":cp["observedAt"]}
        self.assertIn("governance-reconciliation-approval-invalid",verify_case(c)["errors"])
    def test_certificate_invalid(self): c=self.case(); c["longTermReconciliationCertificateValid"]=False; self.assertIn("long-term-reconciliation-certificate-invalid",verify_case(c)["errors"])
    def test_manual_readback_missing(self): c=self.case(); c["independentManualReadbackValid"]=False; self.assertIn("independent-manual-readback-missing",verify_case(c)["errors"])

if __name__=="__main__": unittest.main()
