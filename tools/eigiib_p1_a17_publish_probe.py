from __future__ import annotations

import base64, hashlib, json, os, pathlib, subprocess, tempfile, time
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/p1-a17"
OUT = FIX / "live-durability-evidence.json"
REPO = "Nico59000/EIGIIB-norm"
A16 = "020cbfc29aaeccb51606021669b7f381f2ec00f6"
A16_REPORT = "da7f10bf5055b4e965792f02bfdf4b4add32767214208ad3d05e095fa67c91f5"
A16_CAPSULE = "4e19c204fa557e993d9357cd4e6b1bf7fbd0710ebceaf8aea8f54562cd067406"
MANIFEST = "sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8"
REGISTRY = "ghcr.io/nico59000/eigiib-norm-p1-a16"
REG_REPO = "nico59000/eigiib-norm-p1-a16"
REG_TAG = "p1-a16-fixture-v1"
TAG = "eigiib-p1-a17-recovery-v1"
TITLE = "EIGIIB P1-A17 recovery replica fixture"
BOUNDARY = "named-ghcr-primary-github-release-recovery-retention-and-single-location-restore-closure"
POLICY_SHA = "63dc542b090e27dfac33961aaf81b41c95070a3969a117625e0c9d77573cb983"
KEY_SPKI = "49894e40b8f9a5bbce08be919e88da6c25d5c1bc29f637936ef8ff22721f6b34"
OBJECTS = [
    ("eigiib-p1-a16-oci-manifest.json", "tests/fixtures/p1-a16/oci-manifest.json", MANIFEST, 1493, "manifest"),
    ("eigiib-p1-a16-oci-config.json", None, "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", 2, "blob"),
    ("eigiib-p1-a14-fixed-1.1.archive.txt", "tests/fixtures/p1-a14/fixed-release-archive.txt", "sha256:14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682", 190, "blob"),
    ("eigiib-p1-a14-fixed-1.1.descriptor.json", "tests/fixtures/p1-a14/fixed-release-descriptor.json", "sha256:762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1", 776, "blob"),
    ("eigiib-p1-a15-live-release-manifest.json", "tests/fixtures/p1-a15/live-release-manifest.json", "sha256:82e61dcf91be3cac21d93349e22829f27b1bdca057e813e584a1593c5a7d604b", 1421, "blob"),
]

class Error(RuntimeError): pass

def need(ok, message):
    if not ok: raise Error(message)

def sha(data): return hashlib.sha256(data).hexdigest()
def canon(value): return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
def load(data): return json.loads(data)
def run(*args, input_bytes=None):
    p = subprocess.run(args, input=input_bytes, capture_output=True)
    if p.returncode: raise Error(f"command failed {args}: {p.stderr[:1000]!r}")
    return p.stdout

def gh_json(*args): return load(run("gh", *args))
def find_release():
    for release in gh_json("api", f"repos/{REPO}/releases?per_page=100"):
        if release["tag_name"] == TAG: return release
    return None

def fetch(url, headers=None, statuses=(200,)):
    req = urllib.request.Request(url, headers={"User-Agent":"eigiib-p1-a17-probe/1.0", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=90) as r: status, body, hdrs = r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        status, body, hdrs = e.code, e.read(), dict(e.headers)
    need(status in statuses, f"HTTP {status} for {url}: {body[:500]!r}")
    return status, body, hdrs

def verify_policy():
    policy = (FIX / "retention-policy.json").read_bytes()
    capsule = (FIX / "retention-policy-capsule.json").read_bytes()
    key = (FIX / "retention-policy-public-key.pem").read_bytes()
    need(canon(load(policy)) == policy and sha(policy) == POLICY_SHA, "policy mismatch")
    cap = load(capsule); payload = base64.b64decode(cap["payload"], validate=True); sig = base64.b64decode(cap["signature"], validate=True)
    need(canon(cap) == capsule and canon(load(payload)) == payload, "capsule canonicalization mismatch")
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d); (d/"p").write_bytes(payload); (d/"s").write_bytes(sig); (d/"k").write_bytes(key)
        run("openssl","pkeyutl","-verify","-pubin","-inkey",str(d/"k"),"-rawin","-in",str(d/"p"),"-sigfile",str(d/"s"))
        der = run("openssl","pkey","-pubin","-in",str(d/"k"),"-outform","DER")
    pay = load(payload)
    need(sha(der)==KEY_SPKI and cap["keyId"]=="sha256:"+KEY_SPKI, "policy key mismatch")
    need(pay["retentionPolicySha256"]==POLICY_SHA and pay["sourceP1A16Commit"]==A16 and pay["sourceP1A16ReportSha256"]==A16_REPORT and pay["sourceP1A16CapsuleSha256"]==A16_CAPSULE and pay["recoveryReleaseTag"]==TAG and pay["boundary"]==BOUNDARY, "policy capsule binding mismatch")
    return policy, capsule, key

def ghcr_token():
    q=urllib.parse.urlencode({"service":"ghcr.io","scope":f"repository:{REG_REPO}:pull"})
    _, body, _ = fetch("https://ghcr.io/token?"+q)
    value=load(body); token=value.get("token") or value.get("access_token")
    need(token, "GHCR token missing"); return token

def protected_hash(items):
    return sha(canon([{"name":n,"digest":d,"size":s} for n,_,d,s,_ in items]))

def main():
    if OUT.exists(): print("evidence already captured"); return
    need(os.getenv("GITHUB_TOKEN"), "GITHUB_TOKEN missing")
    need(sha((ROOT/"tests/fixtures/p1-a16/expected-report.json").read_bytes())==A16_REPORT, "A16 report mismatch")
    need(sha((ROOT/"tests/fixtures/p1-a16/capsule.json").read_bytes())==A16_CAPSULE, "A16 capsule mismatch")
    policy, capsule, key = verify_policy()
    data = {}
    for name,path,digest,size,_ in OBJECTS:
        raw=b"{}" if path is None else (ROOT/path).read_bytes()
        need(len(raw)==size and "sha256:"+sha(raw)==digest, f"object mismatch: {name}"); data[name]=raw
    set_hash=protected_hash(OBJECTS)
    existing=find_release()
    if existing is not None:
        need(existing["draft"] is True, "existing recovery release is not a disposable draft")
        run("gh","api","--method","DELETE",f"repos/{REPO}/releases/{existing['id']}")
        subprocess.run(["gh","api","--method","DELETE",f"repos/{REPO}/git/refs/tags/{TAG}"],capture_output=True)
    with tempfile.TemporaryDirectory(prefix="eigiib-p1-a17-") as td:
        td=pathlib.Path(td); files=[]
        for name in data: p=td/name; p.write_bytes(data[name]); files.append(p)
        extras=[("eigiib-p1-a17-retention-policy.json",policy),("eigiib-p1-a17-retention-policy-capsule.json",capsule),("eigiib-p1-a17-retention-policy-public-key.pem",key)]
        for name,raw in extras: p=td/name; p.write_bytes(raw); files.append(p)
        run("gh","release","create",TAG,"--repo",REPO,"--target",A16,"--title",TITLE,"--notes","P1-A17 recovery replica fixture. This records a policy-bound recovery location, not a platform-enforced future availability guarantee.","--draft","--prerelease")
        run("gh","release","upload",TAG,*map(str,files),"--repo",REPO)
        release=find_release(); need(release is not None and release["draft"] is True, "draft release inventory lookup failed")
        assets=release["assets"]
        manifest={"standard":"EIGIIB-P1-A17-RESTORE-MANIFEST-1.0","sourceP1A16":{"commit":A16,"reportSha256":A16_REPORT,"capsuleSha256":A16_CAPSULE,"registry":REGISTRY,"tag":REG_TAG,"manifestDigest":MANIFEST},"retentionPolicy":{"sha256":POLICY_SHA,"capsuleSha256":sha(capsule),"publicKeySpkiSha256":KEY_SPKI},"recoveryRelease":{"repository":REPO,"releaseId":release["id"],"releaseNodeId":release["node_id"],"tag":TAG,"targetCommitish":A16},"protectedObjectSetSha256":set_hash,"protectedObjects":[{"name":n,"digest":d,"size":s} for n,_,d,s,_ in OBJECTS],"assets":[{"name":a["name"],"assetId":a["id"],"size":a["size"],"apiDigest":a.get("digest")} for a in assets],"boundary":BOUNDARY}
        restore=td/"eigiib-p1-a17-restore-manifest.json"; restore.write_bytes(canon(manifest))
        run("gh","release","upload",TAG,str(restore),"--repo",REPO)
        run("gh","api","--method","PATCH",f"repos/{REPO}/releases/{release['id']}","-F","draft=false","-F","prerelease=true","-f",f"name={TITLE}")
    public=None
    for _ in range(15):
        status,body,_=fetch(f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}",statuses=(200,404))
        if status==200: public=load(body); break
        time.sleep(2)
    need(public and not public["draft"] and public["prerelease"], "public release unavailable")
    expected_names=set(data)|{"eigiib-p1-a17-retention-policy.json","eigiib-p1-a17-retention-policy-capsule.json","eigiib-p1-a17-retention-policy-public-key.pem","eigiib-p1-a17-restore-manifest.json"}
    need({a["name"] for a in public["assets"]}==expected_names, "release asset set mismatch")
    release_assets=[]; recovery=[]
    for a in sorted(public["assets"],key=lambda x:x["name"]):
        _,raw,_=fetch(a["browser_download_url"],headers={"Accept":"application/octet-stream"})
        digest=sha(raw); need(len(raw)==a["size"],f"asset size mismatch: {a['name']}")
        if a.get("digest") is not None: need(a["digest"]=="sha256:"+digest,f"asset API digest mismatch: {a['name']}")
        release_assets.append({"name":a["name"],"assetId":a["id"],"nodeId":a["node_id"],"size":a["size"],"apiDigest":a.get("digest"),"sha256":digest,"publicDownloadSha256":digest,"browserDownloadUrl":a["browser_download_url"]})
        for n,_,d,s,_ in OBJECTS:
            if n==a["name"]: need("sha256:"+digest==d and len(raw)==s,f"recovery mismatch: {n}"); recovery.append({"name":n,"digest":d,"size":s})
    ref=gh_json("api",f"repos/{REPO}/git/ref/tags/{TAG}")["object"]
    if ref["type"]=="tag": ref=gh_json("api",f"repos/{REPO}/git/tags/{ref['sha']}")["object"]
    need(ref=={"sha":A16,"type":"commit","url":ref["url"]}, "release tag target mismatch")
    token=ghcr_token(); primary=[]
    for n,_,d,s,kind in OBJECTS:
        path=("manifests/" if kind=="manifest" else "blobs/")+d
        accept="application/vnd.oci.image.manifest.v1+json" if kind=="manifest" else "application/octet-stream"
        _,raw,_=fetch(f"https://ghcr.io/v2/{REG_REPO}/{path}",headers={"Authorization":f"Bearer {token}","Accept":accept})
        need(len(raw)==s and "sha256:"+sha(raw)==d,f"primary mismatch: {n}"); primary.append({"name":n,"digest":d,"size":s})
    expected=sorted([{"name":n,"digest":d,"size":s} for n,_,d,s,_ in OBJECTS],key=lambda x:x["name"])
    need(sorted(primary,key=lambda x:x["name"])==expected and sorted(recovery,key=lambda x:x["name"])==expected,"single-location restore mismatch")
    decisions={"administrativeDeletionPrevention":"not-claimed","correlatedProviderFailureResistance":"not-claimed","declaredRetentionPolicy":"conformant","durableAvailability":"conformant-for-observed-two-location-policy-bound-restore-window","futureAvailabilityGuarantee":"not-claimed","platformEnforcedRetention":"not-claimed","primaryLocationReadback":"conformant-at-capture-time","providerIndependentReplication":"not-claimed","recoveryLocationReadback":"conformant-at-capture-time","replication":"conformant-for-named-cross-service-two-location-scope","singleLocationRestore":"conformant-for-each-named-location-at-capture-time"}
    captured=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
    evidence={"standard":"EIGIIB-P1-A17","capturedAt":captured,"sourceP1A16":{"repository":REPO,"commit":A16,"reportSha256":A16_REPORT,"capsuleSha256":A16_CAPSULE,"registry":REGISTRY,"registryTag":REG_TAG,"manifestDigest":MANIFEST},"retentionPolicy":{"policyId":"eigiib-p1-a17-retention-policy-v1","sha256":POLICY_SHA,"capsuleSha256":sha(capsule),"publicKeySpkiSha256":KEY_SPKI,"minimumRetentionDays":90,"restoreAuditIntervalDays":7},"primaryLocation":{"kind":"oci-registry","locator":f"{REGISTRY}@{MANIFEST}","protectedObjects":expected,"protectedObjectSetSha256":set_hash},"recoveryLocation":{"kind":"github-release","repository":REPO,"releaseId":public["id"],"releaseNodeId":public["node_id"],"tag":TAG,"name":public["name"],"targetCommitish":public["target_commitish"],"tagTargetCommit":ref["sha"],"draft":public["draft"],"prerelease":public["prerelease"],"immutable":public.get("immutable"),"assets":release_assets,"protectedObjects":expected,"protectedObjectSetSha256":set_hash},"restoreReplay":{"primaryOnly":{"result":"conformant","protectedObjectSetSha256":set_hash,"objectCount":len(OBJECTS)},"recoveryOnly":{"result":"conformant","protectedObjectSetSha256":set_hash,"objectCount":len(OBJECTS)},"crossLocationByteIdentity":"conformant"},"decisions":decisions,"boundary":BOUNDARY}
    FIX.mkdir(parents=True,exist_ok=True); OUT.write_bytes(canon(evidence)); print(json.dumps({"releaseId":public["id"],"capturedAt":captured,"result":"conformant"},sort_keys=True))

if __name__ == "__main__": main()
