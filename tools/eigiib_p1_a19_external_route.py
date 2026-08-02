from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from eigiib_p1_a19_common import FIXTURE, canonical_bytes, load_json, sha256_json

parser = argparse.ArgumentParser()
parser.add_argument("--payload", required=True)
parser.add_argument("--signature", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

bundle = load_json(FIXTURE / "interoperability-bundle.json")
signed = bundle["signedRegistry"]
registry = signed["payload"]
Path(args.payload).write_bytes(canonical_bytes(registry))
Path(args.signature).write_bytes(base64.b64decode(signed["signatureBase64"], validate=True))
result = {
    "route": "external-openssl-registry-verification",
    "registrySha256": sha256_json(registry),
    "activeProfileCount": len(registry["activeVersions"]),
    "routeCount": len(bundle["routes"]),
    "decision": "ready-for-external-signature-verification",
}
Path(args.output).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
