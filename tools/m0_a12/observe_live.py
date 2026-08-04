#!/usr/bin/env python3
"""Independent live observer for M0-A12 AWS/GCS channels."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys
TOOLS_ROOT = Path(__file__).resolve().parents[1]
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from eigiib_m0_a12_canonical import digest_document
from eigiib_m0_a12_signature import (
    DEFAULT_NAMESPACE,
    load_allowed_signers,
    load_private_key,
    public_key_raw,
    sign_file,
)

EXPECTED_SHA256 = "96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
EXPECTED_BYTES = 985664
CAMPAIGN_ID = "eigiib-m0-a11-external-preservation-observation-v1"


class ObservationError(RuntimeError):
    pass


def run_json(command: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    if result.returncode != 0:
        raise ObservationError(result.stderr.decode("utf-8", errors="replace").strip() or "command failed")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except Exception as exc:
        raise ObservationError(f"invalid JSON from command: {command[0]}") from exc
    if not isinstance(value, dict):
        raise ObservationError("command JSON result must be an object")
    return value


def run(command: list[str], env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    if result.returncode != 0:
        raise ObservationError(result.stderr.decode("utf-8", errors="replace").strip() or "command failed")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_time(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ObservationError("provider timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def observe_aws(config: dict[str, Any], work: Path, refs: Path) -> dict[str, Any]:
    if not shutil.which("aws"):
        raise ObservationError("aws CLI is required")
    env = os.environ.copy()
    if config.get("profile"):
        env["AWS_PROFILE"] = config["profile"]
    region = config["region"]
    common = ["aws", "--region", region, "--no-cli-pager"]
    bucket, key, version = config["bucket"], config["key"], config["versionId"]
    retention = run_json(common + ["s3api","get-object-retention","--bucket",bucket,"--key",key,"--version-id",version,"--output","json"], env)
    head = run_json(common + ["s3api","head-object","--bucket",bucket,"--key",key,"--version-id",version,"--output","json"], env)
    target = work / "aws-readback.bin"
    run(common + ["s3api","get-object","--bucket",bucket,"--key",key,"--version-id",version,str(target)], env)
    if target.stat().st_size != EXPECTED_BYTES or sha256_file(target) != EXPECTED_SHA256:
        raise ObservationError("AWS readback identity mismatch")
    retention_doc = retention.get("Retention", {})
    if retention_doc.get("Mode") != "COMPLIANCE":
        raise ObservationError("AWS object is not in COMPLIANCE mode")
    retain_until = parse_time(retention_doc.get("RetainUntilDate"))
    if retain_until <= datetime.now(timezone.utc):
        raise ObservationError("AWS retention has expired")
    (refs/"aws-get-object-retention.json").write_text(json.dumps(retention, indent=2, sort_keys=True)+"\n", encoding="utf-8", newline="\n")
    (refs/"aws-head-object.json").write_text(json.dumps(head, indent=2, sort_keys=True)+"\n", encoding="utf-8", newline="\n")
    return {
        "channelId": "immutable-channel-primary",
        "providerResourceId": f"arn:aws:s3:::{bucket}",
        "objectVersionId": version,
        "readbackBytes": EXPECTED_BYTES,
        "readbackSha256": EXPECTED_SHA256,
        "retentionState": "applied-and-readback-verified",
        "result": "exact-and-retained",
        "evidenceRefs": [
            "evidence-refs/aws-get-object-retention.json",
            "evidence-refs/aws-head-object.json",
        ],
    }


def observe_gcs(config: dict[str, Any], work: Path, refs: Path) -> dict[str, Any]:
    if not shutil.which("gcloud"):
        raise ObservationError("gcloud CLI is required")
    prefix = ["gcloud", "--quiet"]
    if config.get("configuration"):
        prefix.append(f"--configuration={config['configuration']}")
    bucket, object_name, generation = config["bucket"], config["object"], str(config["generation"])
    bucket_doc = run_json(prefix + ["storage","buckets","describe",f"gs://{bucket}","--format=json"])
    object_doc = run_json(prefix + ["storage","objects","describe",f"gs://{bucket}/{object_name}#{generation}","--format=json"])
    retention = bucket_doc.get("retentionPolicy", {})
    if retention.get("isLocked") is not True:
        raise ObservationError("GCS retention policy is not locked")
    if str(object_doc.get("generation")) != generation:
        raise ObservationError("GCS generation mismatch")
    expiration = object_doc.get("retentionExpirationTime")
    if not expiration or parse_time(expiration) <= datetime.now(timezone.utc):
        raise ObservationError("GCS retention has expired or is absent")
    target = work / "gcs-readback.bin"
    run(prefix + ["storage","cp",f"gs://{bucket}/{object_name}#{generation}",str(target)])
    if target.stat().st_size != EXPECTED_BYTES or sha256_file(target) != EXPECTED_SHA256:
        raise ObservationError("GCS readback identity mismatch")
    (refs/"gcs-bucket.json").write_text(json.dumps(bucket_doc, indent=2, sort_keys=True)+"\n", encoding="utf-8", newline="\n")
    (refs/"gcs-object.json").write_text(json.dumps(object_doc, indent=2, sort_keys=True)+"\n", encoding="utf-8", newline="\n")
    return {
        "channelId": "immutable-channel-secondary",
        "providerResourceId": f"//storage.googleapis.com/projects/_/buckets/{bucket}",
        "objectVersionId": generation,
        "readbackBytes": EXPECTED_BYTES,
        "readbackSha256": EXPECTED_SHA256,
        "retentionState": "applied-and-readback-verified",
        "result": "exact-and-retained",
        "evidenceRefs": [
            "evidence-refs/gcs-bucket.json",
            "evidence-refs/gcs-object.json",
        ],
    }


def validate_observer_key(private_key_path: Path, allowed_signers_path: Path, key_id: str) -> None:
    private_key = load_private_key(private_key_path)
    public_raw = public_key_raw(private_key.public_key())
    signers = load_allowed_signers(allowed_signers_path)
    signer = signers.get("independent-observer-primary")
    if signer is None or signer.get("keyId") != key_id:
        raise ObservationError("observer key is not bound in allowed signers")
    if base64.b64decode(signer.get("publicKeyRawBase64")) != public_raw:
        raise ObservationError("observer private key does not match bound public key")
    if signer.get("publicKeyDigest") != hashlib.sha256(public_raw).hexdigest():
        raise ObservationError("observer public-key digest mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--allowed-signers", required=True)
    parser.add_argument("--observer-key-id", required=True)
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    refs = output.parent / "evidence-refs"
    refs.mkdir(parents=True, exist_ok=True)
    allowed_signers = Path(args.allowed_signers)
    validate_observer_key(Path(args.private_key), allowed_signers, args.observer_key_id)

    with tempfile.TemporaryDirectory(prefix="m0-a12-observer-") as tmp:
        work = Path(tmp)
        channels = [
            observe_aws(config["aws"], work, refs),
            observe_gcs(config["gcs"], work, refs),
        ]

    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    observation = {
        "standard": "EIGIIB-M0-A12-OBSERVATION-1.0",
        "campaignId": CAMPAIGN_ID,
        "sequence": 1,
        "observedAt": observed_at,
        "previousObservationDigest": None,
        "observerDomainId": "independent-observer-primary",
        "observerKeyId": args.observer_key_id,
        "channels": channels,
        "observationDigest": "",
    }
    observation["observationDigest"] = digest_document(observation, "observationDigest")
    output.write_text(json.dumps(observation, indent=2, sort_keys=False)+"\n", encoding="utf-8", newline="\n")
    sign_file(
        output,
        Path(args.private_key),
        "independent-observer-primary",
        args.observer_key_id,
        "keys/allowed_signers.json",
        DEFAULT_NAMESPACE,
        observed_at,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
