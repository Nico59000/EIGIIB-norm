package p1verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func verifyP1A1(aggregateRaw, p1raw []byte) (map[string]any, []byte, error) {
	av,e:=strictJSON(aggregateRaw);if e!=nil{return nil,nil,e};a:=obj(av);if str(a["standard"])!="EIGIIB-M0-A2-1.0"||str(a["overall_result"])!="conformant"{return nil,nil,errors.New("aggregate constants mismatch")}
	v,e:=strictJSON(p1raw);if e!=nil{return nil,nil,e};c:=obj(v);if str(c["standard"])!="EIGIIB-P1-A1-1.0"||str(c["profile"])!="in-toto-aggregate-export-v1"||str(c["authentication_state"])!="not-provided-p1-a1"||str(c["transport_layer"])!="in-toto-statement-v1"{return nil,nil,errors.New("P1-A1 constants mismatch")}
	st:=obj(c["statement"]);if str(st["_type"])!="https://in-toto.io/Statement/v1"||str(st["predicateType"])!="https://eigiib.example/attestation/aggregate-conformance/v1"{return nil,nil,errors.New("Statement constants mismatch")}
	pred:=obj(st["predicate"]);rep:=obj(pred["aggregateReport"]);raw,e:=b64(str(rep["data"]));if e!=nil{return nil,nil,e};if !bytes.Equal(raw,aggregateRaw)||!eqID(rep["identity"],ident(aggregateRaw)){return nil,nil,errors.New("aggregate report binding mismatch")}
	res:=obj(pred["aggregateResult"]);if str(res["carrier"])!="overall_result"||str(res["value"])!=str(a["overall_result"]){return nil,nil,errors.New("aggregate result carrier mismatch")}
	subs:=arr(st["subject"]);if len(subs)!=1{return nil,nil,errors.New("subject count mismatch")};s:=obj(subs[0]);if str(s["name"])!="tests/fixtures/p1-a1/aggregate.json"||str(obj(s["digest"])["sha256"])!=ident(aggregateRaw).Digest{return nil,nil,errors.New("subject binding mismatch")}
	out,e:=canonicalJSON(st);if e!=nil{return nil,nil,e};if ident(out)!=(Identity{"sha256","d307eb420577bdac5817ca679348cc4f36540dc7fec6c827a02cb626f62c9d4b",1597}){return nil,nil,errors.New("deterministic Statement identity mismatch")};return st,out,nil
}

func readEd25519(path string)(ed25519.PublicKey,[]byte,error){raw,e:=os.ReadFile(path);if e!=nil{return nil,nil,e};block,_:=pem.Decode(raw);if block==nil||block.Type!="PUBLIC KEY"{return nil,nil,errors.New("invalid public key PEM")};v,e:=x509.ParsePKIXPublicKey(block.Bytes);if e!=nil{return nil,nil,e};pk,ok:=v.(ed25519.PublicKey);if !ok||len(pk)!=ed25519.PublicKeySize{return nil,nil,errors.New("key is not Ed25519")};if len(block.Bytes)!=44{return nil,nil,errors.New("Ed25519 SPKI must be 44 bytes")};return pk,block.Bytes,nil}

func verifyP1A2(raw,statement []byte,pk ed25519.PublicKey,der []byte)error{
	v,e:=strictJSON(raw);if e!=nil{return e};c:=obj(v);if str(c["standard"])!="EIGIIB-P1-A2-1.0"||str(c["profile"])!="sigstore-p1-a1-dsse-bundle-v1"||str(c["external_spec"])!="sigstore-bundle-0.3.2"||str(c["trust_scope"])!="supplied-public-key-only"{return errors.New("P1-A2 constants mismatch")}
	binding:=obj(c["binding"]);if !eqID(binding["p1A1Statement"],ident(statement))||!eqID(binding["publicKeySpki"],ident(der)){return errors.New("P1-A2 binding mismatch")};bundle:=obj(c["bundle"]);if str(bundle["mediaType"])!="application/vnd.dev.sigstore.bundle.v0.3+json"{return errors.New("bundle media type mismatch")}
	env:=obj(bundle["dsseEnvelope"]);if str(env["payloadType"])!="application/vnd.in-toto+json"{return errors.New("DSSE payload type mismatch")};payload,e:=b64(str(env["payload"]));if e!=nil{return e};if !bytes.Equal(payload,statement){return errors.New("DSSE payload differs from deterministic P1-A1 Statement")};pv,e:=strictJSON(payload);if e!=nil{return e};can,e:=canonicalJSON(pv);if e!=nil||!bytes.Equal(can,payload){return errors.New("DSSE payload is not canonical JSON")}
	sigs:=arr(env["signatures"]);if len(sigs)!=1{return errors.New("exactly one DSSE signature required")};sigobj:=obj(sigs[0]);sig,e:=b64(str(sigobj["sig"]));if e!=nil{return e};if len(sig)!=64{return errors.New("invalid Ed25519 signature size")};hint:="p1-a2-ed25519-spki-sha256:"+ident(der).Digest;if str(sigobj["keyid"])!=hint||str(obj(obj(bundle["verificationMaterial"])["publicKeyIdentifier"])["hint"])!=hint{return errors.New("public key hint mismatch")};if !ed25519.Verify(pk,pae("application/vnd.in-toto+json",payload),sig){return errors.New("invalid DSSE Ed25519 signature")};return nil
}
