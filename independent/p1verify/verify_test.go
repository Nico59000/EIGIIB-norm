package p1verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)
func repoRoot(t *testing.T)string{t.Helper();root,err:=filepath.Abs("../..");if err!=nil{t.Fatal(err)};return root}
func copyFile(t *testing.T,src,dst string){t.Helper();b,err:=os.ReadFile(src);if err!=nil{t.Fatal(err)};if err=os.MkdirAll(filepath.Dir(dst),0755);err!=nil{t.Fatal(err)};if err=os.WriteFile(dst,b,0644);err!=nil{t.Fatal(err)}}
func fixtureCopy(t *testing.T)string{t.Helper();src:=repoRoot(t);dst:=t.TempDir();files:=[]string{"tests/fixtures/p1-a1/aggregate.json","tests/fixtures/p1-a1/capsule.json","tests/fixtures/p1-a2/bundle.json","tests/fixtures/p1-a2/public-key.pem","tests/fixtures/p1-a3/capsule.json","tests/fixtures/p1-a3/issuer-public-key.pem","tests/fixtures/p1-a3/ts-public-key.pem","tests/fixtures/p1-a4/chain.json"};for _,p:=range files{copyFile(t,filepath.Join(src,p),filepath.Join(dst,p))};return dst}
func TestCanonicalReplay(t *testing.T){r:=Verify(repoRoot(t));if r.EndToEndResult!="conformant"{t.Fatalf("unexpected failure: %+v",r.Findings)}}
func TestTamperedAggregate(t *testing.T){root:=fixtureCopy(t);p:=filepath.Join(root,"tests/fixtures/p1-a1/aggregate.json");b,_:=os.ReadFile(p);b=[]byte(strings.Replace(string(b),"conformant","non-conformant",1));os.WriteFile(p,b,0644);if Verify(root).EndToEndResult=="conformant"{t.Fatal("tampered aggregate accepted")}}
func TestTamperedDSSESignature(t *testing.T){root:=fixtureCopy(t);p:=filepath.Join(root,"tests/fixtures/p1-a2/bundle.json");var v map[string]any;b,_:=os.ReadFile(p);json.Unmarshal(b,&v);s:=v["bundle"].(map[string]any)["dsseEnvelope"].(map[string]any)["signatures"].([]any)[0].(map[string]any);x:=s["sig"].(string);s["sig"]="A"+x[1:];b,_=json.MarshalIndent(v,"","  ");os.WriteFile(p,append(b,'\n'),0644);if Verify(root).EndToEndResult=="conformant"{t.Fatal("tampered DSSE signature accepted")}}
func TestTamperedReceipt(t *testing.T){root:=fixtureCopy(t);p:=filepath.Join(root,"tests/fixtures/p1-a3/capsule.json");var v map[string]any;b,_:=os.ReadFile(p);json.Unmarshal(b,&v);r:=v["receipt"].(map[string]any);x:=r["data"].(string);r["data"]="A"+x[1:];b,_=json.MarshalIndent(v,"","  ");os.WriteFile(p,append(b,'\n'),0644);if Verify(root).EndToEndResult=="conformant"{t.Fatal("tampered receipt accepted")}}
func TestDuplicateManifestMember(t *testing.T){root:=fixtureCopy(t);p:=filepath.Join(root,"tests/fixtures/p1-a4/chain.json");b,_:=os.ReadFile(p);b=[]byte(strings.Replace(string(b),"{\n","{\n  \"standard\": \"duplicate\",\n",1));os.WriteFile(p,b,0644);if Verify(root).EndToEndResult=="conformant"{t.Fatal("duplicate JSON member accepted")}}
func TestPathEscape(t *testing.T){root:=fixtureCopy(t);p:=filepath.Join(root,"tests/fixtures/p1-a4/chain.json");b,_:=os.ReadFile(p);b=[]byte(strings.Replace(string(b),"tests/fixtures/p1-a1/aggregate.json","../../escape",1));os.WriteFile(p,b,0644);if Verify(root).EndToEndResult=="conformant"{t.Fatal("escaping path accepted")}}
func TestWrongIssuerKey(t *testing.T){root:=fixtureCopy(t);src:=filepath.Join(root,"tests/fixtures/p1-a2/public-key.pem");dst:=filepath.Join(root,"tests/fixtures/p1-a3/issuer-public-key.pem");copyFile(t,src,dst);if Verify(root).EndToEndResult=="conformant"{t.Fatal("wrong issuer key accepted")}}
