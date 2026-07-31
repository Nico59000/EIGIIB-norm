import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("e9checker",HERE.parent/"tools"/"eigiib_degraded_check.py")
mod=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=mod; SPEC.loader.exec_module(mod)
Checker=mod.Checker; STANDARD=mod.STANDARD

class Tests(unittest.TestCase):
    def base(self):
        return {"standard":STANDARD,"revision":"test","dependencies":[],"capabilities":[],"modes":[],"observations":[],"fallbacks":[],"policies":[],"decisions":[]}
    def run_obj(self,o,conv=None,files=None):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); (r/"conformance").mkdir(); (r/"conformance/degraded.json").write_text(json.dumps(o)); (r/"conformance/convergence.json").write_text(json.dumps(conv or {"cutover_decisions":[]}))
            for p,t in (files or {}).items(): q=r/p; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(t)
            return Checker(r,Path("conformance/degraded.json"),Path("conformance/convergence.json")).run()
    def valid(self, fallback=False, nominal=False):
        o=self.base(); o["dependencies"]=[{"id":"primary","kind":"authority"},{"id":"backup","kind":"authority"}]
        o["capabilities"]=[{"id":"read","impact":"read","minimum_availability":"degraded","required_dependencies":["primary"]},{"id":"write","impact":"write","minimum_availability":"available","required_dependencies":["primary"]}]
        if nominal:
            o["modes"]=[{"id":"m","kind":"nominal","assurance":"full","allowed_capabilities":["read","write"],"denied_capabilities":[],"preserved_guarantees":["auth"],"suspended_guarantees":[]}]
            o["observations"]=[{"id":"op","dependency":"primary","state":"available","evidence":["probe"]},{"id":"ob","dependency":"backup","state":"available","evidence":["probe"]}]
            o["policies"]=[{"id":"p","mode":"m","required_dependencies":["primary"],"allowed_degraded_dependencies":[],"unknown_disposition":"deny","allowed_capabilities":["read","write"],"require_e8_cutover_for_nominal":False}]
            o["decisions"]=[{"id":"d","state":"nominal-restored","mode":"m","policy":"p","observations":["op"],"fallbacks":[],"capabilities":["read","write"]}]
        else:
            o["modes"]=[{"id":"m","kind":"fallback" if fallback else "degraded","assurance":"partial","allowed_capabilities":["read"],"denied_capabilities":["write"],"preserved_guarantees":["integrity"],"suspended_guarantees":["fresh-auth"]}]
            st="unavailable" if fallback else "degraded"
            o["observations"]=[{"id":"op","dependency":"primary","state":st,"evidence":["probe"]},{"id":"ob","dependency":"backup","state":"available","evidence":["probe"]}]
            o["fallbacks"]=[{"id":"fb","source":"primary","substitute":"backup","state":"active","evidence":["switch"]}] if fallback else []
            o["policies"]=[{"id":"p","mode":"m","required_dependencies":[],"allowed_degraded_dependencies":["primary"],"unknown_disposition":"fallback","allowed_capabilities":["read"],"require_e8_cutover_for_nominal":False}]
            o["decisions"]=[{"id":"d","state":"fallback-verified" if fallback else "degraded-safe","mode":"m","policy":"p","observations":["op","ob"],"fallbacks":["fb"] if fallback else [],"capabilities":["read"]}]
        return o
    def assert_code(self,r,c): self.assertTrue(any(f["code"]==c for f in r["findings"]),r)
    def test_valid_degraded(self): self.assertEqual(self.run_obj(self.valid())["degraded_operation_result"],"verified")
    def test_valid_fallback(self): self.assertEqual(self.run_obj(self.valid(True))["fallback_result"],"verified")
    def test_valid_nominal(self): self.assertEqual(self.run_obj(self.valid(nominal=True))["nominal_restoration_result"],"verified")
    def test_overlap_rejected(self):
        o=self.valid(); o["modes"][0]["denied_capabilities"].append("read"); self.assert_code(self.run_obj(o),"E9.MODE.OVERLAP")
    def test_active_fallback_needs_evidence(self):
        o=self.valid(True); o["fallbacks"][0]["evidence"]=[]; self.assert_code(self.run_obj(o),"E9.FALLBACK.NO_EVIDENCE")
    def test_bad_substitute_rejected(self):
        o=self.valid(True); o["observations"][1]["state"]="unavailable"; self.assert_code(self.run_obj(o),"E9.DECISION.FALLBACK_SUBSTITUTE")
    def test_write_requirement_not_met(self):
        o=self.valid(); o["modes"][0]["denied_capabilities"].remove("write"); o["modes"][0]["allowed_capabilities"].append("write"); o["policies"][0]["allowed_capabilities"].append("write"); o["decisions"][0]["capabilities"].append("write"); self.assert_code(self.run_obj(o),"E9.DECISION.CAP_DEP")
    def test_unknown_not_available(self):
        o=self.valid(); o["observations"][0]["state"]="unknown"; o["policies"][0]["unknown_disposition"]="deny"; self.assert_code(self.run_obj(o),"E9.DECISION.CAP_DEP")
    def test_full_assurance_rejects_degraded(self):
        o=self.valid(); o["modes"][0]["assurance"]="full"; self.assert_code(self.run_obj(o),"E9.DECISION.FULL_ASSURANCE")
    def test_nominal_requires_e8_when_configured(self):
        o=self.valid(nominal=True); o["policies"][0]["require_e8_cutover_for_nominal"]=True; o["decisions"][0]["e8_cutover"]="cut"; self.assert_code(self.run_obj(o),"E9.DECISION.E8")
    def test_path_escape(self):
        o=self.valid(); o["observations"][0]["evidence"]=[{"path":"../x"}]; self.assert_code(self.run_obj(o),"E9.PATH.ESCAPE")
    def test_fallback_state_requires_route(self):
        o=self.valid(); o["modes"][0]["kind"]="fallback"; o["decisions"][0]["state"]="fallback-verified"; self.assert_code(self.run_obj(o),"E9.DECISION.FALLBACK_REQUIRED")
    def test_unknown_fallback_requires_policy(self):
        o=self.valid(True); o["observations"][0]["state"]="unknown"; o["policies"][0]["unknown_disposition"]="deny"; self.assert_code(self.run_obj(o),"E9.DECISION.UNKNOWN_FALLBACK")
    def test_duplicate_dependency_observation_rejected(self):
        o=self.valid(); o["observations"].append({"id":"op2","dependency":"primary","state":"available","evidence":["probe"]}); o["decisions"][0]["observations"].append("op2"); self.assert_code(self.run_obj(o),"E9.DECISION.OBS_DUPLICATE")
    def test_structural_error_suppresses_positive_result(self):
        o=self.valid(); o["dependencies"][0]["kind"]="invalid"; r=self.run_obj(o); self.assertEqual(r["degraded_operation_result"],"not-evaluated")
    def test_valid_partial_trust(self):
        o=self.valid(); o["decisions"][0]["state"]="partial-trust-available"; self.assertEqual(self.run_obj(o)["partial_trust_result"],"verified")
    def test_nominal_e8_cutover_can_resolve(self):
        o=self.valid(nominal=True); o["policies"][0]["require_e8_cutover_for_nominal"]=True; o["decisions"][0]["e8_cutover"]="cut"; r=self.run_obj(o,{"cutover_decisions":[{"id":"cut","state":"verified"}]}); self.assertEqual(r["nominal_restoration_result"],"verified")

if __name__=="__main__": unittest.main()
