import importlib.util, json, sys, tempfile, unittest
from copy import deepcopy
from pathlib import Path

HERE=Path(__file__).resolve().parent
TOOL=HERE.parent/"tools/eigiib_policy_composition_check.py"
spec=importlib.util.spec_from_file_location("e13comp",TOOL)
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
STD=mod.STANDARD

def automation():
    return {
      "contexts":[{"id":"ctx","revision":"ctx-r1"}],
      "policies":[
        {"id":"pa","revision":"pa-r1"},{"id":"pb","revision":"pb-r1"},{"id":"pw","revision":"pw-r1"}
      ],
      "proposals":[
        {"id":"qa","revision":"qa-r1","actor":"alice","requested_executor":"svc","action":"publish","scope":"scope:prod","target":"service:A","policy":"pa","context":"ctx"},
        {"id":"qb","revision":"qb-r1","actor":"alice","requested_executor":"svc","action":"publish","scope":"scope:prod","target":"service:A","policy":"pb","context":"ctx"},
        {"id":"qw","revision":"qw-r1","actor":"security","requested_executor":"svc","action":"eigiib:e13:waive-obligation","scope":"scope:waiver","target":"ob-pre","policy":"pw","context":"ctx"}
      ],
      "decisions":[
        {"id":"da","proposal":"qa","policy":"pa","context":"ctx","state":"authorized","proposal_revision":"qa-r1","policy_revision":"pa-r1","context_revision":"ctx-r1"},
        {"id":"db","proposal":"qb","policy":"pb","context":"ctx","state":"authorized","proposal_revision":"qb-r1","policy_revision":"pb-r1","context_revision":"ctx-r1"},
        {"id":"dw","proposal":"qw","policy":"pw","context":"ctx","state":"authorized","proposal_revision":"qw-r1","policy_revision":"pw-r1","context_revision":"ctx-r1"}
      ]
    }

def registry(algorithm="all-authorized"):
    members=[{"policy":"pa","required":True},{"policy":"pb","required":True}]
    if algorithm=="priority-order":
        members=[{"policy":"pa","required":True,"priority":10},{"policy":"pb","required":True,"priority":20}]
    return {
      "standard":STD,"revision":"test",
      "composition_profiles":[{"id":"cp","revision":"cp-r1","algorithm":algorithm,"members":members,"allow_obligation_waivers":True}],
      "requests":[{"id":"r1","revision":"r1","profile":"cp","action":"publish","scope":"scope:prod","target":"service:A","actor":"alice","requested_executor":"svc","context":"ctx","context_revision":"ctx-r1","decisions":["da","db"]}],
      "obligation_definitions":[],
      "obligation_evaluations":[],
      "exceptions":[],
      "decisions":[{"id":"c1","request":"r1","profile":"cp","state":"permitted"}]
    }

class E13Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); (self.root/"conformance").mkdir()
    def tearDown(self): self.tmp.cleanup()
    def run_obj(self, reg=None, auto=None):
        reg=deepcopy(reg if reg is not None else registry()); auto=deepcopy(auto if auto is not None else automation())
        (self.root/"conformance/policy-composition.json").write_text(json.dumps(reg))
        (self.root/"conformance/automation.json").write_text(json.dumps(auto))
        return mod.Checker(self.root,Path("conformance/policy-composition.json"),Path("conformance/automation.json")).run()
    def code(self,r,c): self.assertTrue(any(x["code"]==c for x in r["findings"]),r)

    def test_empty_structural_registry(self):
        e={"standard":STD,"revision":"empty","composition_profiles":[],"requests":[],"obligation_definitions":[],"obligation_evaluations":[],"exceptions":[],"decisions":[]}
        r=self.run_obj(e,{"policies":[],"contexts":[],"proposals":[],"decisions":[]})
        self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["composition_result"],"not-evaluated")

    def test_all_authorized_permits(self):
        r=self.run_obj(); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["composition_result"],"verified")

    def test_all_authorized_conflict_denies(self):
        a=automation(); a["decisions"][1]["state"]="denied"; x=registry(); x["decisions"][0]["state"]="denied"
        r=self.run_obj(x,a); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["conflict_observation_result"],"verified")

    def test_deny_overrides_conflict_denies(self):
        a=automation(); a["decisions"][1]["state"]="denied"; x=registry("deny-overrides"); x["decisions"][0]["state"]="denied"
        self.assertEqual(self.run_obj(x,a)["structural_result"],"conformant")

    def test_permit_overrides_conflict_permits(self):
        a=automation(); a["decisions"][1]["state"]="denied"; x=registry("permit-overrides")
        r=self.run_obj(x,a); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["composition_result"],"verified")

    def test_priority_order_uses_highest_priority_member(self):
        x=registry("priority-order"); a=automation(); a["decisions"][1]["state"]="denied"
        r=self.run_obj(x,a); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["composition_result"],"verified")

    def test_priority_order_duplicate_priority_rejected(self):
        x=registry("priority-order"); x["composition_profiles"][0]["members"][1]["priority"]=10
        self.code(self.run_obj(x),"E13.PROFILE.PRIORITY_DUPLICATE")

    def test_priority_for_non_priority_algorithm_rejected(self):
        x=registry(); x["composition_profiles"][0]["members"][0]["priority"]=1
        self.code(self.run_obj(x),"E13.PROFILE.PRIORITY_UNUSED")

    def test_profile_requires_two_members(self):
        x=registry(); x["composition_profiles"][0]["members"]=x["composition_profiles"][0]["members"][:1]
        self.code(self.run_obj(x),"E13.PROFILE.MEMBERS")

    def test_profile_requires_one_required_member(self):
        x=registry()
        for m in x["composition_profiles"][0]["members"]: m["required"]=False
        self.code(self.run_obj(x),"E13.PROFILE.REQUIRED_EMPTY")

    def test_action_substitution_rejected(self):
        x=registry(); x["requests"][0]["action"]="delete"; self.code(self.run_obj(x),"E13.REQUEST.SUBJECT_BINDING")

    def test_actor_substitution_rejected(self):
        x=registry(); x["requests"][0]["actor"]="mallory"; self.code(self.run_obj(x),"E13.REQUEST.SUBJECT_BINDING")

    def test_context_revision_stale_rejected(self):
        x=registry(); x["requests"][0]["context_revision"]="ctx-old"; self.code(self.run_obj(x),"E13.REQUEST.CONTEXT_REVISION")

    def test_duplicate_policy_decision_rejected(self):
        a=automation(); d=deepcopy(a["decisions"][0]); d["id"]="da2"; a["decisions"].append(d)
        x=registry(); x["requests"][0]["decisions"]=["da","da2","db"]
        self.code(self.run_obj(x,a),"E13.REQUEST.POLICY_DUPLICATE")

    def test_nonmember_policy_decision_rejected(self):
        x=registry(); x["requests"][0]["decisions"].append("dw")
        self.code(self.run_obj(x),"E13.REQUEST.POLICY_MEMBER")

    def test_missing_required_member_is_held_not_malformed(self):
        x=registry(); x["requests"][0]["decisions"]=["da"]; x["decisions"][0]["state"]="held"
        r=self.run_obj(x); self.assertEqual(r["structural_result"],"conformant")

    def test_pending_predecision_obligation_blocks_permit(self):
        x=registry(); x["obligation_definitions"]=[{"id":"ob-pre","profile":"cp","source_policy":"pa","phase":"pre-decision","trigger":"authorized","mandatory":True,"waivable":True}]
        x["obligation_evaluations"]=[{"id":"oe","request":"r1","obligation":"ob-pre","state":"pending"}]; x["decisions"][0]["state"]="held"
        self.assertEqual(self.run_obj(x)["structural_result"],"conformant")

    def test_satisfied_predecision_obligation_permits(self):
        x=registry(); x["obligation_definitions"]=[{"id":"ob-pre","profile":"cp","source_policy":"pa","phase":"pre-decision","trigger":"authorized","mandatory":True,"waivable":True}]
        x["obligation_evaluations"]=[{"id":"oe","request":"r1","obligation":"ob-pre","state":"satisfied","evidence":["done"]}]
        self.assertEqual(self.run_obj(x)["composition_result"],"verified")

    def test_valid_waiver_permits(self):
        x=registry(); x["obligation_definitions"]=[{"id":"ob-pre","profile":"cp","source_policy":"pa","phase":"pre-decision","trigger":"authorized","mandatory":True,"waivable":True}]
        x["exceptions"]=[{"id":"ex","request":"r1","obligation":"ob-pre","kind":"obligation-waiver","e10_decision":"dw","state":"active","evidence":["waiver-proof"]}]
        x["obligation_evaluations"]=[{"id":"oe","request":"r1","obligation":"ob-pre","state":"waived","exception":"ex"}]
        self.assertEqual(self.run_obj(x)["composition_result"],"verified")

    def test_waiver_not_allowed_rejected(self):
        x=registry(); x["composition_profiles"][0]["allow_obligation_waivers"]=False
        x["obligation_definitions"]=[{"id":"ob-pre","profile":"cp","source_policy":"pa","phase":"pre-decision","trigger":"authorized","mandatory":True,"waivable":True}]
        x["exceptions"]=[{"id":"ex","request":"r1","obligation":"ob-pre","kind":"obligation-waiver","e10_decision":"dw","state":"active","evidence":["waiver-proof"]}]
        self.code(self.run_obj(x),"E13.EXCEPTION.NOT_ALLOWED")

    def test_waiver_requires_authorized_e10_decision(self):
        a=automation(); a["decisions"][2]["state"]="denied"
        x=registry(); x["obligation_definitions"]=[{"id":"ob-pre","profile":"cp","source_policy":"pa","phase":"pre-decision","trigger":"authorized","mandatory":True,"waivable":True}]
        x["exceptions"]=[{"id":"ex","request":"r1","obligation":"ob-pre","kind":"obligation-waiver","e10_decision":"dw","state":"active","evidence":["waiver-proof"]}]
        self.code(self.run_obj(x,a),"E13.EXCEPTION.AUTHORIZATION")

    def test_duplicate_active_waiver_rejected(self):
        x=registry(); x["obligation_definitions"]=[{"id":"ob-pre","profile":"cp","source_policy":"pa","phase":"pre-decision","trigger":"authorized","mandatory":True,"waivable":True}]
        ex={"request":"r1","obligation":"ob-pre","kind":"obligation-waiver","e10_decision":"dw","state":"active","evidence":["waiver-proof"]}
        x["exceptions"]=[dict(ex,id="ex1"),dict(ex,id="ex2")]
        self.code(self.run_obj(x),"E13.EXCEPTION.MULTIPLE")

    def test_postcommit_pending_is_residual_not_blocker(self):
        x=registry(); x["obligation_definitions"]=[{"id":"ob-post","profile":"cp","source_policy":"pa","phase":"post-commit","trigger":"authorized","mandatory":True,"waivable":False}]
        x["obligation_evaluations"]=[{"id":"oe","request":"r1","obligation":"ob-post","state":"pending"}]
        r=self.run_obj(x); self.assertEqual(r["composition_result"],"verified"); self.assertEqual(r["residual_obligation_result"],"verified")

    def test_declared_outcome_mismatch_rejected(self):
        x=registry(); x["decisions"][0]["state"]="denied"; self.code(self.run_obj(x),"E13.DECISION.DERIVATION")

    def test_multiple_composed_decisions_for_request_rejected(self):
        x=registry(); x["decisions"].append({"id":"c2","request":"r1","profile":"cp","state":"permitted"})
        self.code(self.run_obj(x),"E13.DECISION.DUPLICATE_REQUEST")

    def test_all_unavailable_maps_unavailable(self):
        a=automation(); a["decisions"][0]["state"]="unavailable"; a["decisions"][1]["state"]="unavailable"
        x=registry(); x["decisions"][0]["state"]="unavailable"; self.assertEqual(self.run_obj(x,a)["structural_result"],"conformant")

    def test_structural_error_suppresses_positive_result(self):
        x=registry(); x["requests"][0]["target"]="other"; r=self.run_obj(x)
        self.assertEqual(r["structural_result"],"non-conformant"); self.assertEqual(r["composition_result"],"not-evaluated")

if __name__=="__main__": unittest.main()
