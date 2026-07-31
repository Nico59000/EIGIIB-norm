import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("e10checker",HERE.parent/"tools"/"eigiib_automation_check.py")
mod=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=mod; SPEC.loader.exec_module(mod)
Checker=mod.Checker; STANDARD=mod.STANDARD

class AutomationTests(unittest.TestCase):
    def base(self):
        return {
            "standard":STANDARD,"revision":"test",
            "principals":[],"delegations":[],"contexts":[],"policies":[],"proposals":[],
            "approvals":[],"decisions":[],"executions":[],"effects":[],"accountability_traces":[]
        }

    def valid(self):
        o=self.base()
        o["principals"]=[
            {"id":"actor","kind":"service","status":"active","direct_scopes":["mutate"]},
            {"id":"reviewer","kind":"human","status":"active","direct_scopes":["approve-mutate"]},
            {"id":"worker","kind":"service","status":"active","direct_scopes":["mutate"]},
            {"id":"root","kind":"human","status":"active","direct_scopes":["mutate","approve-mutate"]},
        ]
        o["contexts"]=[{"id":"ctx","revision":"c1"}]
        o["policies"]=[{
            "id":"pol","revision":"r1","action_scope":"mutate","approval_scope":"approve-mutate",
            "required_approvals":1,"allow_self_approval":False,"allow_automation_actor":False,
            "allow_automation_executor":False,"max_delegation_depth":3,
            "require_e9_context":False,"allowed_e9_states":["nominal-restored"]
        }]
        o["proposals"]=[{
            "id":"p","revision":"p1","actor":"actor","requested_executor":"worker",
            "action":"deploy","scope":"mutate","target":"svc","policy":"pol","context":"ctx"
        }]
        o["approvals"]=[{
            "id":"a","proposal":"p","approver":"reviewer","state":"approved",
            "proposal_revision":"p1","policy_revision":"r1","context_revision":"c1",
            "authority_path":[],"evidence":["approval-evidence"]
        }]
        o["decisions"]=[{
            "id":"d","proposal":"p","policy":"pol","context":"ctx","state":"authorized",
            "proposal_revision":"p1","policy_revision":"r1","context_revision":"c1",
            "actor_authority_path":[],"approvals":["a"]
        }]
        o["executions"]=[{
            "id":"x","decision":"d","executor":"worker","state":"succeeded",
            "authority_path":[],"evidence":["execution-evidence"]
        }]
        o["effects"]=[{"id":"f","execution":"x","state":"observed","evidence":["effect-evidence"]}]
        o["accountability_traces"]=[{
            "id":"t","decision":"d","execution":"x","effect":"f",
            "participants":["actor","worker","reviewer"],"state":"trace-complete"
        }]
        return o

    def run_obj(self,obj,degraded=None,files=None):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"conformance").mkdir(); (root/"tools").mkdir()
            (root/"conformance/automation.json").write_text(json.dumps(obj),encoding="utf-8")
            (root/"conformance/degraded.json").write_text(json.dumps(degraded or {"decisions":[]}),encoding="utf-8")
            for p,text in (files or {}).items():
                q=root/p; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(text,encoding="utf-8")
            return Checker(root,Path("conformance/automation.json"),Path("conformance/degraded.json")).run()

    def codes(self,r): return {f["code"] for f in r["findings"]}

    def test_valid_full_trace(self):
        r=self.run_obj(self.valid())
        self.assertEqual(r["structural_result"],"conformant")
        self.assertEqual(r["authorization_result"],"verified")
        self.assertEqual(r["execution_result"],"verified")
        self.assertEqual(r["effect_result"],"observed")
        self.assertEqual(r["accountability_result"],"verified")

    def test_valid_delegated_actor(self):
        o=self.valid(); o["principals"][0]["direct_scopes"]=[]
        o["delegations"]=[{"id":"g","delegator":"root","delegate":"actor","scopes":["mutate"],"status":"active"}]
        o["decisions"][0]["actor_authority_path"]=["g"]
        r=self.run_obj(o)
        self.assertEqual(r["structural_result"],"conformant")
        self.assertEqual(r["delegation_result"],"verified")

    def test_stale_approval_rejected(self):
        o=self.valid(); o["approvals"][0]["proposal_revision"]="old"
        self.assertIn("E10.APPROVAL.PROPOSAL_REV",self.codes(self.run_obj(o)))

    def test_quorum_rejected(self):
        o=self.valid(); o["policies"][0]["required_approvals"]=2
        self.assertIn("E10.DECISION.QUORUM",self.codes(self.run_obj(o)))

    def test_self_approval_rejected(self):
        o=self.valid(); o["approvals"][0]["approver"]="actor"; o["principals"][0]["direct_scopes"].append("approve-mutate")
        self.assertIn("E10.APPROVAL.SELF",self.codes(self.run_obj(o)))

    def test_automation_actor_rejected(self):
        o=self.valid(); o["principals"][0]["kind"]="automation"
        self.assertIn("E10.DECISION.AUTOMATION_ACTOR",self.codes(self.run_obj(o)))

    def test_automation_executor_rejected(self):
        o=self.valid(); o["principals"][2]["kind"]="automation"
        self.assertIn("E10.EXECUTION.AUTOMATION",self.codes(self.run_obj(o)))

    def test_required_e9_context_missing(self):
        o=self.valid(); o["policies"][0]["require_e9_context"]=True
        self.assertIn("E10.DECISION.E9_MISSING",self.codes(self.run_obj(o)))

    def test_disallowed_e9_state(self):
        o=self.valid(); o["policies"][0]["require_e9_context"]=True; o["contexts"][0]["e9_decision"]="e9"
        degraded={"decisions":[{"id":"e9","state":"partial-trust-available"}]}
        self.assertIn("E10.DECISION.E9_STATE",self.codes(self.run_obj(o,degraded)))

    def test_execution_requires_mechanically_valid_authorization(self):
        o=self.valid(); o["decisions"][0]["policy_revision"]="stale"
        self.assertIn("E10.EXECUTION.AUTHORIZATION",self.codes(self.run_obj(o)))

    def test_succeeded_execution_requires_evidence(self):
        o=self.valid(); o["executions"][0]["evidence"]=[]
        self.assertIn("E10.EVIDENCE.EMPTY",self.codes(self.run_obj(o)))

    def test_observed_effect_requires_evidence(self):
        o=self.valid(); o["effects"][0]["evidence"]=[]
        self.assertIn("E10.EVIDENCE.EMPTY",self.codes(self.run_obj(o)))

    def test_complete_trace_requires_all_participants(self):
        o=self.valid(); o["accountability_traces"][0]["participants"]=["actor","worker"]
        self.assertIn("E10.TRACE.PARTICIPANTS",self.codes(self.run_obj(o)))

    def test_delegation_cycle_rejected(self):
        o=self.valid(); o["proposals"][0]["actor"]="root"; o["decisions"][0]["actor_authority_path"]=["g1","g2"]
        o["delegations"]=[
            {"id":"g1","delegator":"root","delegate":"actor","scopes":["mutate"],"status":"active"},
            {"id":"g2","delegator":"actor","delegate":"root","scopes":["mutate"],"status":"active"},
        ]
        self.assertIn("E10.AUTH.CYCLE",self.codes(self.run_obj(o)))

    def test_path_escape_rejected(self):
        o=self.valid(); o["approvals"][0]["evidence"]=[{"path":"../escape"}]
        self.assertIn("E10.PATH.ESCAPE",self.codes(self.run_obj(o)))

    def test_empty_evidence_object_rejected(self):
        o=self.valid(); o["approvals"][0]["evidence"]=[{}]
        self.assertIn("E10.EVIDENCE.ITEM",self.codes(self.run_obj(o)))

    def test_empty_registry_conforms(self):
        r=self.run_obj(self.base())
        self.assertEqual(r["structural_result"],"conformant")
        self.assertEqual(r["authorization_result"],"not-evaluated")

    def test_explicit_e9_reference_must_resolve(self):
        o=self.valid(); o["contexts"][0]["e9_decision"]="missing"
        self.assertIn("E10.DECISION.E9_REF",self.codes(self.run_obj(o)))

    def test_suspended_intermediate_principal_rejected(self):
        o=self.valid(); o["principals"][0]["direct_scopes"]=[]
        o["principals"].append({"id":"mid","kind":"service","status":"suspended","direct_scopes":[]})
        o["delegations"]=[
            {"id":"g1","delegator":"root","delegate":"mid","scopes":["mutate"],"status":"active"},
            {"id":"g2","delegator":"mid","delegate":"actor","scopes":["mutate"],"status":"active"},
        ]
        o["decisions"][0]["actor_authority_path"]=["g1","g2"]
        self.assertIn("E10.AUTH.PATH_STATUS",self.codes(self.run_obj(o)))

    def test_requested_executor_self_approval_rejected(self):
        o=self.valid(); o["approvals"][0]["approver"]="worker"; o["principals"][2]["direct_scopes"].append("approve-mutate")
        self.assertIn("E10.APPROVAL.SELF",self.codes(self.run_obj(o)))

    def test_structural_error_suppresses_positive_results(self):
        o=self.valid(); o["delegations"]=[{"id":"bad","delegator":"root","delegate":"root","scopes":["mutate"],"status":"active"}]
        r=self.run_obj(o)
        self.assertEqual(r["structural_result"],"non-conformant")
        self.assertEqual(r["authorization_result"],"not-evaluated")
        self.assertEqual(r["execution_result"],"not-evaluated")
        self.assertEqual(r["accountability_result"],"not-evaluated")

    def test_required_e9_policy_needs_allowed_states(self):
        o=self.valid(); o["policies"][0]["require_e9_context"]=True; o["policies"][0]["allowed_e9_states"]=[]; o["contexts"][0]["e9_decision"]="e9"
        degraded={"decisions":[{"id":"e9","state":"nominal-restored"}]}
        self.assertIn("E10.POLICY.E9_STATES",self.codes(self.run_obj(o,degraded)))

    def test_denied_decision_still_requires_traceable_boundary(self):
        o=self.valid()
        o["decisions"]=[{
            "id":"d","proposal":"missing","policy":"pol","context":"ctx","state":"denied",
            "proposal_revision":"p1","policy_revision":"r1","context_revision":"c1",
            "actor_authority_path":[],"approvals":[]
        }]
        o["executions"]=[]; o["effects"]=[]; o["accountability_traces"]=[]
        self.assertIn("E10.DECISION.REF",self.codes(self.run_obj(o)))

if __name__=="__main__":
    unittest.main()
