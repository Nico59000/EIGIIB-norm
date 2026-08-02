from __future__ import annotations

import argparse
import base64
from pathlib import Path

from eigiib_p1_a20_core import FIXTURE, canonical_bytes, load_bundle, sha256_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("p1-a20-external"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    bundle = load_bundle()
    envelopes = {
        "runner-registry": bundle["signedRunnerRegistry"],
        "toolchain-registry": bundle["signedToolchainRegistry"],
        "rollback-authorization": bundle["signedRollbackAuthorizations"][0],
    }
    for name, envelope in envelopes.items():
        payload = envelope["payload"]
        if envelope["payloadSha256"] != sha256_json(payload):
            raise ValueError(f"{name} digest mismatch")
        (args.output_dir / f"{name}.json").write_bytes(canonical_bytes(payload))
        (args.output_dir / f"{name}.sig").write_bytes(base64.b64decode(envelope["signatureBase64"], validate=True))
    print("P1-A20 external signature materialization: PASS")


if __name__ == "__main__":
    main()
