import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("e9h",HERE.parent/"tools"/"eigiib_degraded_hardening_check.py")
mod=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=mod;SPEC.loader.exec_module(mod)
Checker=mod.Checker;STANDARD=mod.STANDARD

class T(unittest.TestCase):
    def base(self):
        return {"standard":STANDARD,"revision":"test","dependencies":[{"id":"a"},{"id":"b"}],"capabilities":[{"id":"write","minimum_availability":"available","required_dependencies":["a"]}],"modes":[{"id":"m","preserved_guarantees":["integrity"],"suspended_guarantees":["freshness"]}],"observations":[{"id":"oa","dependency":"a","state":"unavailable","evidence":["x"]},{"id":"ob","dependency":"b","state":"available","evidence":["x"]}],"fallbacks":[{"id":"f","source":"a","substitute":"b","state":"active","evidence":["x"]}],"policies":[],"decisions":[{"id":"d","state":"fallback-verified","observations":["oa","ob"],"fallbacks":["f"],"capabilities":["write"]}]}
    def run_obj(self,o,files=None):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td);(r/"conformance").mkdir();(r/"conformance/degraded.json").write_text(json.dumps(o))
            for p,t in (files or {}).items():q=r/p;q.parent.mkdir(parents=True,exist_ok=True);q.write_text(t)
            return Checker(r,Path("conformance/degraded.json")).run()
    def code(self,r,c):self.assertTrue(any(x["code"]==c for x in r["findings"]),r)
    def test_valid(self):self.assertEqual(self.run_obj(self.base())["hardening_result"],"conformant")
    def test_empty_observation_evidence_object(self):
        o=self.base();o["observations"][0]["evidence"]=[{}];self.code(self.run_obj(o),"E9H.OBS.EVIDENCE")
    def test_empty_fallback_evidence_object(self):
        o=self.base();o["fallbacks"][0]["evidence"]=[{}];self.code(self.run_obj(o),"E9H.FALLBACK.EVIDENCE")
    def test_guarantee_overlap(self):
        o=self.base();o["modes"][0]["preserved_guarantees"].append("freshness");self.code(self.run_obj(o),"E9H.MODE.GUARANTEE_OVERLAP")
    def test_degraded_substitute_rejected_for_available_minimum(self):
        o=self.base();o["observations"][1]["state"]="degraded";self.code(self.run_obj(o),"E9H.CAP.FALLBACK_MINIMUM")

if __name__=="__main__":unittest.main()
