import copy
import json
import pathlib
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parents[1]
if TOOLS.name != "tools":
    # Local development layout; repository tests override this with ROOT/tools.
    candidate = pathlib.Path(__file__).resolve().parents[1]
else:
    candidate = TOOLS
ROOT = pathlib.Path(__file__).resolve().parents[1]
repo_tools = ROOT / "tools"
if repo_tools.is_dir():
    sys.path.insert(0, str(repo_tools))
else:
    sys.path.insert(0, str(ROOT))
import eigiib_interop_chain as p1a4


class P1A4Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        for rel in ["tests/fixtures/p1-a1", "tests/fixtures/p1-a2", "tests/fixtures/p1-a3",
                    "tests/fixtures/p1-a4", "tools", "conformance"]:
            (self.root / rel).mkdir(parents=True, exist_ok=True)
        for checker, _version in p1a4.CHECKER_CONTRACT.values():
            (self.root / checker).write_text("# fixture checker\n", encoding="utf-8")
        self._build_fixture()

    def tearDown(self):
        self.tmp.cleanup()

    def _write_json(self, rel, obj):
        raw = (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()
        (self.root / rel).write_bytes(raw)
        return raw

    def _build_fixture(self):
        agg_raw = self._write_json(p1a4.COMPONENT_PATHS["m0-a2-report"],
                                   {"standard": "EIGIIB-M0-A2-1.0", "overall_result": "conformant"})
        agg_ident = p1a4.identity(agg_raw)
        statement = {"_type": "https://in-toto.io/Statement/v1",
                     "predicate": {"aggregateReport": {"identity": agg_ident}}}
        statement_ident = p1a4.identity(p1a4.canonical_json_bytes(statement))
        p1a1_raw = self._write_json(p1a4.COMPONENT_PATHS["p1-a1-statement"],
                                    {"standard": "EIGIIB-P1-A1-1.0", "statement": statement})
        key_idents = {"p1-a2-public-key": p1a4.identity(b"A" * 44),
                      "p1-a3-issuer-key": p1a4.identity(b"B" * 44),
                      "p1-a3-transparency-service-key": p1a4.identity(b"C" * 44)}
        for kid, (path, _role) in p1a4.KEY_CONTRACT.items():
            (self.root / path).write_bytes((kid + "\n").encode())
        p1a2 = {"standard": "EIGIIB-P1-A2-1.0",
                "binding": {"p1A1Statement": statement_ident,
                            "publicKeySpki": key_idents["p1-a2-public-key"]}}
        p1a2_raw = self._write_json(p1a4.COMPONENT_PATHS["p1-a2-bundle"], p1a2)
        p1a2_ident = p1a4.identity(p1a2_raw)
        signed_ident, receipt_ident = p1a4.identity(b"signed-statement"), p1a4.identity(b"receipt")
        p1a3 = {"standard": "EIGIIB-P1-A3-1.0", "binding": {"p1A2Bundle": p1a2_ident},
                "signedStatement": {"identity": signed_ident, "issuerKeySpki": key_idents["p1-a3-issuer-key"]},
                "receipt": {"identity": receipt_ident,
                            "transparencyServiceKeySpki": key_idents["p1-a3-transparency-service-key"]}}
        self._write_json(p1a4.COMPONENT_PATHS["p1-a3-signed-statement"], p1a3)
        components = [
            {"id": "m0-a2-report", "path": p1a4.COMPONENT_PATHS["m0-a2-report"], "standard": p1a4.COMPONENT_STANDARDS["m0-a2-report"], "identity": agg_ident},
            {"id": "p1-a1-statement", "path": p1a4.COMPONENT_PATHS["p1-a1-statement"], "standard": p1a4.COMPONENT_STANDARDS["p1-a1-statement"], "identity": statement_ident},
            {"id": "p1-a2-bundle", "path": p1a4.COMPONENT_PATHS["p1-a2-bundle"], "standard": p1a4.COMPONENT_STANDARDS["p1-a2-bundle"], "identity": p1a2_ident},
            {"id": "p1-a3-signed-statement", "path": p1a4.COMPONENT_PATHS["p1-a3-signed-statement"], "standard": p1a4.COMPONENT_STANDARDS["p1-a3-signed-statement"], "identity": signed_ident},
            {"id": "p1-a3-receipt", "path": p1a4.COMPONENT_PATHS["p1-a3-receipt"], "standard": p1a4.COMPONENT_STANDARDS["p1-a3-receipt"], "identity": receipt_ident},
        ]
        keys = [{"id": kid, "path": p1a4.KEY_CONTRACT[kid][0], "role": p1a4.KEY_CONTRACT[kid][1],
                 "spkiIdentity": key_idents[kid]} for kid in p1a4.KEY_IDS]
        checkers = [{"id": cid, "path": p1a4.CHECKER_CONTRACT[cid][0],
                     "toolVersion": p1a4.CHECKER_CONTRACT[cid][1]} for cid in p1a4.REPLAY_ORDER]
        self.manifest = {"standard": p1a4.STANDARD, "profile": p1a4.PROFILE, "status": p1a4.CHAIN_STATUS,
                         "components": components, "keys": keys,
                         "replay": {"order": p1a4.REPLAY_ORDER[:], "subjectName": p1a4.SUBJECT_NAME,
                                    "checkers": checkers,
                                    "chainIdentity": {"algorithm": "sha256", "digest": "0" * 64, "bytes": 1}},
                         "claimBoundary": {"authority": "p1_chain_contract", "compositionOnly": True,
                                           "doesNotImply": p1a4.BOUNDARIES[:]}}
        self.refresh(self.manifest)
        self._write_json("tests/fixtures/p1-a4/chain.json", self.manifest)
        self.state = {"standard": p1a4.STANDARD, "status": "structural-only", "profile": p1a4.PROFILE,
                      "chain_manifest": "tests/fixtures/p1-a4/chain.json",
                      "execution_scope": "fixed-repository-checkers-only", "network_mode": "none",
                      "production_replays": []}
        self._write_json("conformance/p1-a4-chain.json", self.state)
        self.p1a1_raw = p1a1_raw

    def refresh(self, manifest):
        manifest["replay"]["chainIdentity"] = p1a4.identity(p1a4.canonical_json_bytes(p1a4.chain_descriptor(manifest)))

    def fake_bytes(self, command, cwd):
        return 0, (cwd / p1a4.COMPONENT_PATHS["p1-a1-statement"]).read_bytes(), ""

    def fake_json(self, command, cwd):
        if command[1] == p1a4.CHECKER_CONTRACT["p1-a1"][0]:
            return 0, {"tool_version": "0.2.0", "structural_result": "conformant", "findings": []}, ""
        if command[1] == p1a4.CHECKER_CONTRACT["p1-a2"][0]:
            return 0, {"tool_version": "0.1.1", "structural_result": "conformant", "signature_result": "valid", "findings": []}, ""
        return 0, {"tool_version": "0.2.0", "hardening_result": "conformant",
                   "upstream_p1a2_authentication_result": "valid", "p1a3_baseline_result": "conformant",
                   "findings": []}, ""

    def validate(self, manifest=None, json_runner=None, bytes_runner=None):
        return p1a4.validate_chain(self.root, manifest or self.manifest, "openssl",
                                   json_runner or self.fake_json, bytes_runner or self.fake_bytes)

    @staticmethod
    def codes(out):
        return {x["code"] for x in out["findings"]}
