import json,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EV="2030-01-01T12:00:00Z"
class TestIDPA3(unittest.TestCase):
    def tool(self,name,path):
        r=subprocess.run([sys.executable,str(ROOT/name),str(ROOT/path),"--evaluation-at",EV,"--json"],capture_output=True,text=True)
        return json.loads(r.stdout)["result"]
    def test_positive_both(self):
        p="conformance/idp-a3-access-policy.json"
        self.assertEqual(self.tool("tools/eigiib_idp_a3_check.py",p),"CONFORMANT")
        self.assertEqual(self.tool("tools/eigiib_idp_a3_independent.py",p),"CONFORMANT")
    def test_matrix(self):
        r=subprocess.run([sys.executable,str(ROOT/"tools/eigiib_idp_a3_matrix.py"),str(ROOT),"--json"],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(json.loads(r.stdout)["result"],"CONFORMANT")
    def test_no_host_clock(self):
        for name in ["tools/eigiib_idp_a3_check.py","tools/eigiib_idp_a3_independent.py"]:
            t=(ROOT/name).read_text()
            self.assertNotIn("datetime.now",t)
            self.assertNotIn("time.time",t)
if __name__=="__main__":unittest.main()
