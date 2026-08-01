package p1verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func strictJSON(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw)); d.UseNumber(); v, e := parseJSON(d); if e != nil { return nil, e }
	if _, e = d.Token(); e != io.EOF { return nil, errors.New("trailing JSON data") }; return v, nil
}
func parseJSON(d *json.Decoder) (any, error) {
	t, e := d.Token(); if e != nil { return nil, e }
	if q, ok := t.(json.Delim); ok { switch q {
	case '{': m:=map[string]any{}; for d.More(){ kt,e:=d.Token(); if e!=nil{return nil,e}; k,ok:=kt.(string); if !ok{return nil,errors.New("JSON object key is not string")}; if _,dup:=m[k];dup{return nil,fmt.Errorf("duplicate JSON member: %s",k)}; v,e:=parseJSON(d); if e!=nil{return nil,e}; m[k]=v }; if _,e=d.Token();e!=nil{return nil,e}; return m,nil
	case '[': a:=[]any{}; for d.More(){v,e:=parseJSON(d);if e!=nil{return nil,e};a=append(a,v)}; if _,e=d.Token();e!=nil{return nil,e}; return a,nil }}
	return t,nil
}
func canonicalJSON(v any)([]byte,error){var b bytes.Buffer;e:=json.NewEncoder(&b);e.SetEscapeHTML(false);if err:=e.Encode(v);err!=nil{return nil,err};return bytes.TrimSuffix(b.Bytes(),[]byte("\n")),nil}
func b64(s string)([]byte,error){x,e:=base64.StdEncoding.DecodeString(s);if e!=nil{return nil,e};if base64.StdEncoding.EncodeToString(x)!=s{return nil,errors.New("non-canonical base64")};return x,nil}
func pae(pt string,p []byte)[]byte{return []byte("DSSEv1 "+strconv.Itoa(len(pt))+" "+pt+" "+strconv.Itoa(len(p))+" "+string(p))}
func confined(root,rel string)(string,error){if rel==""||filepath.IsAbs(rel){return "",errors.New("path must be repository-relative")};p:=filepath.Clean(filepath.Join(root,filepath.FromSlash(rel)));rp,e:=filepath.Rel(root,p);if e!=nil||rp==".."||strings.HasPrefix(rp,".."+string(filepath.Separator)){return "",errors.New("path escapes repository root")};return p,nil}
func verifyManifest(root string,m map[string]any)error{
	if str(m["standard"])!="EIGIIB-P1-A4-1.0"||str(m["profile"])!="p1-end-to-end-cross-capsule-replay-v1"||str(m["status"])!="fixture-replay"{return errors.New("manifest constants mismatch")}
	rp:=obj(m["replay"]);desc:=map[string]any{"components":m["components"],"keys":m["keys"],"replayOrder":rp["order"],"subjectName":rp["subjectName"],"checkers":rp["checkers"]};cb,e:=canonicalJSON(desc);if e!=nil{return e};if !eqID(rp["chainIdentity"],ident(cb))||len(cb)!=chainBytes||ident(cb).Digest!=chainDigest{return errors.New("canonical chain identity mismatch")}
	expected:=[]string{"p1-a1","p1-a2","p1-a3-h0.2"};oa:=arr(rp["order"]);if len(oa)!=3{return errors.New("replay order length mismatch")};for i,x:=range expected{if str(oa[i])!=x{return errors.New("replay order mismatch")}};if str(rp["subjectName"])!="tests/fixtures/p1-a1/aggregate.json"{return errors.New("subject name mismatch")}
	comps:=arr(m["components"]);if len(comps)!=5{return errors.New("component count mismatch")};for _,v:=range comps{c:=obj(v);p,e:=confined(root,str(c["path"]));if e!=nil{return e};if _,e=os.Stat(p);e!=nil{return e}}
	keys:=arr(m["keys"]);if len(keys)!=3{return errors.New("key count mismatch")};for _,v:=range keys{k:=obj(v);p,e:=confined(root,str(k["path"]));if e!=nil{return e};_,der,e:=readEd25519(p);if e!=nil{return e};if !eqID(k["spkiIdentity"],ident(der)){return fmt.Errorf("key identity mismatch: %s",str(k["id"]))}}
	b:=obj(m["claimBoundary"]);if str(b["authority"])!="p1_chain_contract"||b["compositionOnly"]!=true{return errors.New("claim boundary mode mismatch")};return nil
}
