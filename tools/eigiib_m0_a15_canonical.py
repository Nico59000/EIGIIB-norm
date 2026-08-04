#!/usr/bin/env python3
import json
def canonical_bytes(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
