import json, shutil, tempfile, unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from eigiib_m0_a13_check import evaluate
from eigiib_m0_a13_replay import verify_case

F5_HEAD = "58945ceab905cb515dff076227bb2b387f907461"
FREEZE_ID = "eigiib-m0-final-freeze-v1"
COLLEGES = ("normative-authority-college","operational-governance-college","independent-verification-college")

class M0A13Tests(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp())
        freeze = json.loads((ROOT/"conformance/m0-a13-authority-freeze.json").read_text())
        for entry in freeze["authorities"]:
            rel = entry["path"]
            src = ROOT / rel
            dst = self.t / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        shutil.copy2(ROOT/"conformance/m0-a13-authority-freeze.json", self.t/"conformance/m0-a13-authority-freeze.json")
        src = ROOT/"conformance/m0-a12-f5-ledger.json"
        if src.exists():
            shutil.copy2(src, self.t/"conformance/m0-a12-f5-ledger.json")

    def tearDown(self):
        shutil.rmtree(self.t)

    def case(self):
        digest = "a" * 64
        approvals = []
        for ci, college in enumerate(COLLEGES):
            for i in range(4):
                approvals.append({
                    "collegeId": college,
                    "approverId": f"{college}-approver-{i}",
                    "controlDomainId": f"{college}-domain-{i}",
                    "requestDigest": digest
                })
        return {
            "f5Decision":"frozen",
            "freezeId":FREEZE_ID,
            "freezeReadbackValid":True,
            "maintenanceClass":"normative-correction",
            "affectedPaths":["conformance/example.json"],
            "implementedPaths":["conformance/example.json"],
            "requestDigest":digest,
            "approvals":approvals,
            "issuedAt":"2026-08-04T12:00:00Z",
            "expiresAt":"2026-08-06T12:00:00Z",
            "executedAt":"2026-08-05T12:00:00Z",
            "revoked":False,
            "predecessorHead":F5_HEAD,
            "successorHead":"1"*40,
            "inPlaceMutation":False,
            "independentVerificationValid":True,
            "supersessionRecordValid":True,
            "staleAuthorityReplay":"rejected",
            "refreezeManifestValid":True,
            "independentRefreezeReadbackValid":True,
            "workflowConclusions":["success"]*15,
            "closureCertificateValid":True
        }

    def test_canonical_baseline(self):
        self.assertEqual(evaluate(self.t), json.loads((ROOT/"tests/fixtures/m0-a13/expected-baseline-report.json").read_text()))

    def test_require_state_is_not_t(self):
        self.assertEqual(evaluate(self.t)["htntLabel"], "NF")

    def test_premature_evidence_is_nt(self):
        p=self.t/"evidence/m0-a13/maintenance-cycle.json"; p.parent.mkdir(parents=True); p.write_text(json.dumps(self.case()))
        self.assertEqual(evaluate(self.t)["htntLabel"], "NT")

    def test_source_head_mutation_is_f(self):
        p=self.t/"conformance/m0-a13-maintenance-authority.json"; d=json.loads(p.read_text()); d["source"]["m0A12F5Head"]="0"*40; p.write_text(json.dumps(d))
        self.assertEqual(evaluate(self.t)["htntLabel"], "F")

    def test_authority_freeze_mutation_is_f(self):
        target=self.t/"conformance/m0-a13-maintenance-policy.json"
        target.write_text(target.read_text()+"\n")
        self.assertEqual(evaluate(self.t)["htntLabel"], "F")

    def test_freeze_id_mutation_is_f(self):
        p=self.t/"conformance/m0-a13-maintenance-authority.json"; d=json.loads(p.read_text()); d["source"]["finalFreezeId"]="other"; p.write_text(json.dumps(d))
        self.assertEqual(evaluate(self.t)["htntLabel"], "F")

    def test_complete_synthetic_cycle(self):
        self.assertTrue(verify_case(self.case())["verified"])

    def test_requires_f5_frozen(self):
        c=self.case(); c["f5Decision"]="not-frozen"; self.assertIn("f5-not-frozen", verify_case(c)["errors"])

    def test_requires_freeze_readback(self):
        c=self.case(); c["freezeReadbackValid"]=False; self.assertIn("freeze-readback-missing", verify_case(c)["errors"])

    def test_scope_rejects_wildcards(self):
        c=self.case(); c["affectedPaths"]=["conformance/*.json"]; c["implementedPaths"]=c["affectedPaths"]; self.assertIn("scope-not-exact", verify_case(c)["errors"])

    def test_scope_expansion_is_rejected(self):
        c=self.case(); c["implementedPaths"].append("tools/extra.py"); self.assertIn("scope-expansion-or-omission", verify_case(c)["errors"])

    def test_each_college_requires_four(self):
        c=self.case(); c["approvals"]=[a for a in c["approvals"] if not (a["collegeId"]==COLLEGES[0] and a["approverId"].endswith("-3"))]
        self.assertIn(f"{COLLEGES[0]}-threshold-not-met", verify_case(c)["errors"])

    def test_each_college_requires_distinct_domains(self):
        c=self.case()
        for a in c["approvals"]:
            if a["collegeId"]==COLLEGES[1]: a["controlDomainId"]="same"
        self.assertIn(f"{COLLEGES[1]}-control-domains-not-independent", verify_case(c)["errors"])

    def test_colleges_must_approve_identical_request(self):
        c=self.case(); c["approvals"][0]["requestDigest"]="b"*64
        self.assertIn(f"{COLLEGES[0]}-request-digest-mismatch", verify_case(c)["errors"])

    def test_cross_college_approver_overlap_rejected(self):
        c=self.case(); c["approvals"][4]["approverId"]=c["approvals"][0]["approverId"]
        self.assertIn("cross-college-approver-overlap", verify_case(c)["errors"])

    def test_expired_authority_rejected(self):
        c=self.case(); c["executedAt"]="2026-08-07T12:00:00Z"
        self.assertIn("reopening-expired", verify_case(c)["errors"])

    def test_excessive_lifetime_rejected(self):
        c=self.case(); c["expiresAt"]="2026-08-20T12:00:00Z"
        self.assertIn("reopening-lifetime-exceeded", verify_case(c)["errors"])

    def test_revoked_authority_rejected(self):
        c=self.case(); c["revoked"]=True
        self.assertIn("reopening-revoked", verify_case(c)["errors"])

    def test_in_place_mutation_rejected(self):
        c=self.case(); c["inPlaceMutation"]=True
        self.assertIn("in-place-mutation-forbidden", verify_case(c)["errors"])

    def test_successor_must_be_distinct(self):
        c=self.case(); c["successorHead"]=F5_HEAD
        self.assertIn("successor-head-invalid", verify_case(c)["errors"])

    def test_independent_verification_required(self):
        c=self.case(); c["independentVerificationValid"]=False
        self.assertIn("independent-verification-missing", verify_case(c)["errors"])

    def test_supersession_record_required(self):
        c=self.case(); c["supersessionRecordValid"]=False
        self.assertIn("supersession-record-invalid", verify_case(c)["errors"])

    def test_stale_authority_must_be_rejected(self):
        c=self.case(); c["staleAuthorityReplay"]="accepted"
        self.assertIn("stale-authority-not-rejected", verify_case(c)["errors"])

    def test_refreeze_manifest_required(self):
        c=self.case(); c["refreezeManifestValid"]=False
        self.assertIn("refreeze-manifest-invalid", verify_case(c)["errors"])

    def test_independent_refreeze_readback_required(self):
        c=self.case(); c["independentRefreezeReadbackValid"]=False
        self.assertIn("independent-refreeze-readback-missing", verify_case(c)["errors"])

    def test_all_workflows_must_be_green(self):
        c=self.case(); c["workflowConclusions"][2]="failure"
        self.assertIn("workflow-inventory-not-green", verify_case(c)["errors"])

    def test_closure_certificate_required(self):
        c=self.case(); c["closureCertificateValid"]=False
        self.assertIn("maintenance-closure-certificate-invalid", verify_case(c)["errors"])

if __name__ == "__main__":
    unittest.main()
