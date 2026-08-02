from __future__ import annotations
import argparse,json,pathlib
from eigiib_p1_a17_common import canonical,need
p=argparse.ArgumentParser();p.add_argument('routes',nargs='+');p.add_argument('--output');a=p.parse_args();need(len(a.routes)==4,'four routes required')
values=[json.loads(pathlib.Path(x).read_text()) for x in a.routes]
for v in values:need(set(v)=={'standard','route','observed','portable'} and v['standard']=='EIGIIB-P1-A17-ROUTE-RESULT-1.0','route shape mismatch')
names=sorted(v['route'] for v in values);need(len(set(names))==4,'duplicate route');portable=values[0]['portable'];need(all(v['portable']==portable for v in values),'portable route divergence')
out={'standard':'EIGIIB-P1-A17-REPLAY-1.0','routeCount':4,'routes':names,'portable':portable,'overallResult':'conformant'};data=canonical(out)
if a.output:pathlib.Path(a.output).write_bytes(data)
print(data.decode(),end='')
