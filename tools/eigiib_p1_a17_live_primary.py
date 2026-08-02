from __future__ import annotations
import json
from eigiib_p1_a17_common import live_primary,route
print(json.dumps(route('reference-python-ghcr',{'location':'primary','objects':live_primary()}),sort_keys=True,separators=(',',':')))
