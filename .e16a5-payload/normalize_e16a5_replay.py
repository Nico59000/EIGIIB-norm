from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPLAY = Path("tools/eigiib_historical_e16_a4_replay.py")
FREEZE = Path("conformance/e16-a5-authority-freeze.json")
OLD_BYTES = 4361
OLD_SHA256 = "09e04d6cbd801273f50ffebc17dd6b24fd26c9f910fab0bc8fe616f788a36f34"
NEW_BYTES = 4363
NEW_SHA256 = "6ff59ed97605136b1af6f049d76c50902c86fabe2226f0b2701f10f9266b7377"
OLD = 'f"{source_commit}^{commit}"'
NEW = 'f"{source_commit}^{{commit}}"'

before = REPLAY.read_bytes()
if len(before) != OLD_BYTES or hashlib.sha256(before).hexdigest() != OLD_SHA256:
    raise SystemExit("unexpected pre-normalization E16-A4 replay identity")
text = before.decode("utf-8")
if text.count(OLD) != 1:
    raise SystemExit("E16-A4 replay normalization cardinality mismatch")
REPLAY.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
after = REPLAY.read_bytes()
if len(after) != NEW_BYTES or hashlib.sha256(after).hexdigest() != NEW_SHA256:
    raise SystemExit("unexpected normalized E16-A4 replay identity")

freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
authorities = freeze.get("authorities")
if freeze.get("authority_count") != 95 or not isinstance(authorities, list) or len(authorities) != 95:
    raise SystemExit("E16-A5 freeze cardinality mismatch")
matches = [item for item in authorities if item.get("path") == REPLAY.as_posix()]
if len(matches) != 1:
    raise SystemExit("E16-A4 replay freeze entry cardinality mismatch")
entry = matches[0]
if entry.get("bytes") != OLD_BYTES or entry.get("sha256") != OLD_SHA256:
    raise SystemExit("unexpected pre-normalization replay freeze entry")
entry["bytes"] = NEW_BYTES
entry["sha256"] = NEW_SHA256
FREEZE.write_text(json.dumps(freeze, indent=2) + "\n", encoding="utf-8")

paths = [item.get("path") for item in authorities]
if len(paths) != len(set(paths)) or FREEZE.as_posix() in paths:
    raise SystemExit("invalid E16-A5 freeze path set")
for item in authorities:
    path = Path(item["path"])
    if not path.is_file():
        raise SystemExit(f"missing frozen authority: {path}")
    raw = path.read_bytes()
    if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
        raise SystemExit(f"frozen authority mismatch: {path}")
