#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from eigiib_p1_a16_common import (
    BOUNDARY,
    FIXTURE_DIR,
    ROOT,
    SOURCE_A15_CAPSULE_SHA256,
    SOURCE_A15_COMMIT,
    SOURCE_A15_REPORT_SHA256,
    sha256_file,
    spki_sha256,
    validate_fixture,
)


def report(root: pathlib.Path = ROOT) -> dict:
    portable = validate_fixture(root)
    fixture = root / "tests/fixtures/p1-a16"
    return {
        "standard": "EIGIIB-P1-A16-REPORT-1.0",
        "sourceP1A15Commit": SOURCE_A15_COMMIT,
        "sourceP1A15ReportSha256": SOURCE_A15_REPORT_SHA256,
        "sourceP1A15CapsuleSha256": SOURCE_A15_CAPSULE_SHA256,
        "evidenceSha256": sha256_file(fixture / "live-registry-evidence.json"),
        "ociManifestSha256": sha256_file(fixture / "oci-manifest.json"),
        "capsuleSha256": sha256_file(fixture / "capsule.json"),
        "evidenceRegistrarSpkiSha256": spki_sha256(fixture / "evidence-registrar-public-key.pem"),
        "portable": portable,
        "overallResult": "conformant",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        value = report()
    except Exception as exc:
        print(f"P1-A16 validation failed: {exc}", file=sys.stderr)
        return 1
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        pathlib.Path(args.output).write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
