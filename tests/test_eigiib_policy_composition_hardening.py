import importlib.util, json, sys, tempfile, unittest
from copy import deepcopy
from pathlib import Path

HERE=Path(__file__).resolve().parent
BASETOOL=HERE.parent/"tools/eigiib_policy_composition_check.py"
HARD=HERE.parent/"tools/eigiib_policy_composition_hardening_check.py"
spec=importlib.util.spec_from_file_location("e13base",BASETOOL); base=importlib.util.module_from_spec(spec); sys.modules[spec.name]=base; spec.loader.exec_module(base)
spec2=importlib.util.spec_from_file_location("e13hard",HARD); mod=importlib.util.module_from_spec(spec2); sys.modules[spec2.name]=mod; spec2.loader.exec_module(mod)

def automation():
    return {
      "contexts":[{"id":"ctx","revision":"ctx-r1"},{"id":"ctx2","revision":"ctx2-r1"}],
      "policies":[{"id":"pa","revision":"pa-r1"},{"id":"pb","revision":"pb-r1"},{"id":"pw","revision":"pw-r1"}],
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

def registry(alg="permit-overrides", with_waiver=False):
    members=[{"policy":"pa","required":True},{"policy":"pb","required":True}]
    if alg=="priority-order": members=[{"policy":"pa","required":True,"priority":10},{"policy":"pb","required":True,"priority":20}]
    x={"standard":base.STANDARD,"revision":"test",
       "composition_profiles":[{"id":"cp","revision":"1","algorithm":alg,"members":members,"allow_obligation_waivers":True}],
       "requests":[{"id":"r1","revision":"1","profile":"cp","action":"publish","scope":"scope:prod","target":"service:A","actor":"alice","requested_executor":"svc","context":"ctx","context_revision":"ctx-r1","decisions":["da","db"]}],
       "obligation_definitions":[],"obligation_evaluations":[],"exceptions":[],
       "decisions":[{"id":"c1","request":"r1","profile":"cp","state":"permitted"}]}
    if with_waiver:
        x["obligation_definitions"]=[{"id":"ob-pre","profile":"cp","source_policy":"pa","phase":"pre-decision","trigger":"authorized","mandatory":True,"waivable":True}]
        x["exceptions"]=[{"id":"ex","request":"r1","obligation":"ob-pre","kind":"obligation-waiver","e10_decision":"dw","state":"active","evidence":["proof"]}]
        x["obligation_evaluations"]=[{"id":"oe","request":"r1","obligation":"ob-pre","state":"waived","exception":"ex"}]
    return x

class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name); (self.root/"conformance").mkdir(); (self.root/"tools").mkdir()
        (self.root/"tools/eigiib_policy_composition_check.py").write_text(BASETOOL.read_text())
    def tearDown(self): self.t.cleanup()
    def run_obj(self,r=None,a=None):
        r=deepcopy(r if r is not None else registry()); a=deepcopy(a if a is not None else automation())
        (self.root/"conformance/policy-composition.json").write_text(json.dumps(r))
        (self.root/"conformance/automation.json").write_text(json.dumps(a))
        return mod.Checker(self.root,Path("conformance/policy-composition.json"),Path("conformance/automation.json")).run()
    def code(self,r,c): self.assertTrue(any(f["code"]==c for f in r["findings"]),r)
    def test_positive_conclusive_required_members(self):
        r=self.run_obj(); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["required_member_result"],"verified")
    def test_permit_overrides_cannot_bypass_required_unavailable(self):
        a=automation(); a["decisions"][1]["state"]="unavailable"; self.code(self.run_obj(a=a),"E13H.REQUIRED.CONCLUSIVE")
    def test_priority_order_cannot_bypass_required_unavailable(self):
        a=automation(); a["decisions"][1]["state"]="unavailable"; x=registry("priority-order"); self.code(self.run_obj(x,a),"E13H.REQUIRED.CONCLUSIVE")
    def test_required_denied_is_conclusive_for_explicit_permit_overrides(self):
        a=automation(); a["decisions"][1]["state"]="denied"; r=self.run_obj(a=a); self.assertEqual(r["structural_result"],"conformant")
    def test_unknown_selected_e10_state_rejected(self):
        a=automation(); a["decisions"][1]["state"]="mystery"; self.code(self.run_obj(a=a),"E13H.UPSTREAM.STATE")
    def test_valid_waiver_context_passes(self):
        r=self.run_obj(registry(with_waiver=True)); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["waiver_context_result"],"verified")
    def test_waiver_other_context_rejected(self):
        a=automation(); a["proposals"][2]["context"]="ctx2"; a["decisions"][2]["context"]="ctx2"; a["decisions"][2]["context_revision"]="ctx2-r1"
        self.code(self.run_obj(registry(with_waiver=True),a),"E13H.WAIVER.CONTEXT")
    def test_waiver_stale_context_revision_rejected(self):
        a=automation(); a["decisions"][2]["context_revision"]="old"
        self.code(self.run_obj(registry(with_waiver=True),a),"E13H.WAIVER.CONTEXT_REVISION")

if __name__=="__main__": unittest.main()
