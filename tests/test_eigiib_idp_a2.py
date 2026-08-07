import importlib.util, json, pathlib, unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
REF=load(ROOT/"tools/eigiib_idp_a2_check.py","ref")
IND=load(ROOT/"tools/eigiib_idp_a2_independent.py","ind")
MATRIX=load(ROOT/"tools/eigiib_idp_a2_matrix.py","matrix")

class IDPA2Tests(unittest.TestCase):
    def test_registry_conformant(self):
        data=json.loads((ROOT/"conformance/idp-a2-bridge-binding.json").read_text(encoding="utf-8"))
        self.assertEqual([],REF.validate(data))
        self.assertEqual([],IND.validate(data))
    def test_frozen_vectors(self):
        matrix=json.loads((ROOT/"conformance/idp-a2-verifier-matrix.json").read_text(encoding="utf-8"))
        base=json.loads((ROOT/matrix["baseline"]).read_text(encoding="utf-8"))
        for v in matrix["vectors"]:
            with self.subTest(v=v["id"]):
                data=MATRIX.mutate(base,v["mutations"])
                rr="CONFORMANT" if not REF.validate(data) else "NON_CONFORMANT"
                ir="CONFORMANT" if not IND.validate(data) else "NON_CONFORMANT"
                self.assertEqual(v["expected"],rr)
                self.assertEqual(v["expected"],ir)
    def test_context_commitments_are_exact(self):
        data=json.loads((ROOT/"conformance/idp-a2-bridge-binding.json").read_text(encoding="utf-8"))
        for b in data["bindings"]:
            ctx={k:b[k] for k in ["channelId","direction","localPrincipalId","remotePrincipalId","localEndpointId","remoteEndpointId","transportProfileId","expectedPinsetId","allowedClasses"]}
            self.assertEqual(b["contextCommitment"],REF.canon_sha(ctx))
if __name__=="__main__": unittest.main()
