from __future__ import annotations
import json
from eigiib_p1_a17_common import live_recovery,route
print(json.dumps(route('reference-python-github-release',{'location':'recovery','objects':live_recovery()}),sort_keys=True,separators=(',',':')))
