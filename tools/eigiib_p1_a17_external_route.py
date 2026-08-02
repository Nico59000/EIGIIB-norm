from __future__ import annotations
import json,pathlib,subprocess,tempfile
from eigiib_p1_a17_common import OBJECTS,REGISTRY,RELEASE_TAG,ROOT,need,route,sha

def run(*args):
 p=subprocess.run(args,capture_output=True)
 if p.returncode:raise SystemExit(f'command failed {args}: {p.stderr[:1000]!r}')
 return p.stdout
with tempfile.TemporaryDirectory(prefix='eigiib-p1-a17-cli-') as d:
 d=pathlib.Path(d); primary=[]
 for name,digest,size,kind in OBJECTS:
  out=d/('p-'+name)
  if kind=='manifest': run('oras','manifest','fetch',f'{REGISTRY}@{digest}','--output',str(out))
  else: run('oras','blob','fetch',f'{REGISTRY}@{digest}','--output',str(out))
  b=out.read_bytes();need(len(b)==size and 'sha256:'+sha(b)==digest,'ORAS mismatch: '+name);primary.append({'name':name,'digest':digest,'size':size})
 rec=d/'release';rec.mkdir()
 for name,digest,size,_ in OBJECTS:
  run('gh','release','download',RELEASE_TAG,'--repo','Nico59000/EIGIIB-norm','--pattern',name,'--dir',str(rec))
  b=(rec/name).read_bytes();need(len(b)==size and 'sha256:'+sha(b)==digest,'gh mismatch: '+name)
print(json.dumps(route('external-oras-gh-cli',{'primaryObjects':primary,'recoveryObjectCount':len(OBJECTS)}),sort_keys=True,separators=(',',':')))
