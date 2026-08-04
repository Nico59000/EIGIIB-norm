#!/usr/bin/env python3
"""Verify and bind a closed M0-A12-F1 external-evidence package."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from eigiib_m0_a12_f1_canonical import (
    digest_document,
    inventory_digest,
    safe_relative_path,
    sha256_bytes,
    sha256_file,
)

STANDARD = "EIGIIB-M0-A12-F1-EVIDENCE-PACK-MANIFEST-1.0"
RECEIPT_STANDARD = "EIGIIB-M0-A12-F1-INGRESS-RECEIPT-1.0"
APPROVAL_STANDARD = "EIGIIB-M0-A12-F1-OPERATOR-APPROVAL-1.0"
M0_A12_HEAD = "e6661993924aed4d0185df48cf0b8587b2e0abf3"
PACKAGE_ROOT = "m0-a12-f1-package"
MANIFEST_PATH = f"{PACKAGE_ROOT}/manifest.json"
MANIFEST_SIGNATURE_PATH = f"{PACKAGE_ROOT}/manifest.json.sig"
PAYLOAD_PREFIX = f"{PACKAGE_ROOT}/payload/"
ALLOWED_SIGNERS_PATH = f"{PAYLOAD_PREFIX}evidence/m0-a12/keys/allowed_signers.json"
APPROVAL_PATH = f"{PAYLOAD_PREFIX}evidence/m0-a12-f1/operator-approval.json"
APPROVAL_SIGNATURES = {
    "external-preservation-primary": APPROVAL_PATH + ".primary.sig",
    "external-preservation-secondary": APPROVAL_PATH + ".secondary.sig",
    "independent-observer-primary": APPROVAL_PATH + ".observer.sig",
}
INGRESS_NAMESPACE = "eigiib-m0-a12-f1-ingress@eigiib.example"
APPROVAL_NAMESPACE = "eigiib-m0-a12-f1-approval@eigiib.example"
BIND_CONFIRMATION = "BIND-M0-A12-F1-EXTERNAL-EVIDENCE"
MAX_MEMBERS = 512
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
REQUIRED_M0_A12_PAYLOADS = {
    "control-domains/external-preservation-primary.json",
    "control-domains/external-preservation-primary.json.sig",
    "control-domains/external-preservation-secondary.json",
    "control-domains/external-preservation-secondary.json.sig",
    "control-domains/independent-observer-primary.json",
    "control-domains/independent-observer-primary.json.sig",
    "keys/allowed_signers.json",
    "channels/immutable-channel-primary.json",
    "channels/immutable-channel-secondary.json",
    "diversity-matrix.json",
    "campaign-anchor.json",
    "observations/000001.json",
    "observations/000001.json.sig",
}


class IngressError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IngressError(f"cannot parse JSON: {path}") from exc
    if not isinstance(value, dict):
        raise IngressError(f"JSON root must be an object: {path}")
    return value


def _validate_member_name(name: str) -> PurePosixPath:
    try:
        path = safe_relative_path(name)
    except ValueError as exc:
        raise IngressError(f"unsafe archive path: {name!r}") from exc
    if path.parts[0] != PACKAGE_ROOT:
        raise IngressError(f"archive member outside {PACKAGE_ROOT}: {name}")
    return path


def read_archive(archive: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    try:
        handle = tarfile.open(archive, mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        raise IngressError("cannot open evidence package") from exc
    with handle:
        members = handle.getmembers()
        if len(members) > MAX_MEMBERS:
            raise IngressError("archive member limit exceeded")
        for member in members:
            path = _validate_member_name(member.name)
            normalized = path.as_posix()
            if member.isdir():
                continue
            if not member.isfile():
                raise IngressError(f"non-regular archive member rejected: {normalized}")
            if normalized in files:
                raise IngressError(f"duplicate archive member: {normalized}")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise IngressError(f"archive member size rejected: {normalized}")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise IngressError("archive expanded-size limit exceeded")
            stream = handle.extractfile(member)
            if stream is None:
                raise IngressError(f"cannot read archive member: {normalized}")
            data = stream.read(MAX_MEMBER_BYTES + 1)
            if len(data) != member.size or len(data) > MAX_MEMBER_BYTES:
                raise IngressError(f"archive member length mismatch: {normalized}")
            files[normalized] = data
    return files


def write_isolated(files: dict[str, bytes], root: Path) -> None:
    for rel, data in files.items():
        destination = root / PurePosixPath(rel)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def _entry_projection(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": item.get("path"),
        "bytes": item.get("bytes"),
        "sha256": item.get("sha256"),
        "role": item.get("role"),
        "mediaType": item.get("mediaType"),
    }


def _verify_signature(
    payload: Path,
    signature: Path,
    allowed: Path,
    identity: str,
    namespace: str,
    expected_signed_path: str,
) -> None:
    try:
        from eigiib_m0_a12_signature import SignatureError, verify_file
    except Exception as exc:
        raise IngressError("cryptographic verifier is unavailable") from exc
    envelope = load_object(signature)
    if envelope.get("signedPayloadPath") != expected_signed_path:
        raise IngressError(f"signed payload path mismatch for {identity}")
    try:
        verify_file(payload, signature, allowed, identity, namespace)
    except (OSError, SignatureError) as exc:
        raise IngressError(f"signature verification failed for {identity}") from exc


def verify_package(archive: Path) -> dict[str, Any]:
    files = read_archive(archive)
    required_top = {MANIFEST_PATH, MANIFEST_SIGNATURE_PATH, ALLOWED_SIGNERS_PATH, APPROVAL_PATH}
    required_top.update(APPROVAL_SIGNATURES.values())
    missing = sorted(required_top - files.keys())
    if missing:
        raise IngressError("required package members missing: " + ", ".join(missing))
    extras_outside_payload = sorted(
        path for path in files
        if path not in {MANIFEST_PATH, MANIFEST_SIGNATURE_PATH} and not path.startswith(PAYLOAD_PREFIX)
    )
    if extras_outside_payload:
        raise IngressError("unexpected package members: " + ", ".join(extras_outside_payload))

    with tempfile.TemporaryDirectory(prefix="eigiib-m0-a12-f1-") as temporary:
        root = Path(temporary)
        write_isolated(files, root)
        manifest_path = root / MANIFEST_PATH
        manifest = load_object(manifest_path)
        if manifest.get("standard") != STANDARD:
            raise IngressError("invalid evidence-pack manifest standard")
        if manifest.get("sourceAuthorityHead") != M0_A12_HEAD:
            raise IngressError("evidence pack is bound to the wrong M0-A12 head")
        if manifest.get("packageRoot") != PACKAGE_ROOT:
            raise IngressError("package root mismatch")
        if manifest.get("payloadPrefix") != "payload/":
            raise IngressError("payload prefix mismatch")
        if manifest.get("manifestDigest") != digest_document(manifest, "manifestDigest"):
            raise IngressError("manifest digest mismatch")

        entries = manifest.get("entries")
        if not isinstance(entries, list) or not entries:
            raise IngressError("manifest entries must be a non-empty list")
        projected = [_entry_projection(item) for item in entries if isinstance(item, dict)]
        if len(projected) != len(entries):
            raise IngressError("manifest entry type mismatch")
        paths = [item["path"] for item in projected]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise IngressError("manifest entries must be unique and lexicographically sorted")
        expected_payload_paths = sorted(path[len(PACKAGE_ROOT) + 1:] for path in files if path.startswith(PAYLOAD_PREFIX))
        if paths != expected_payload_paths:
            raise IngressError("manifest inventory does not exactly match archive payload")
        for item in projected:
            path = item["path"]
            try:
                safe_relative_path(path)
            except ValueError as exc:
                raise IngressError(f"unsafe manifest path: {path!r}") from exc
            if not path.startswith("payload/"):
                raise IngressError(f"manifest path outside payload: {path}")
            data = files[f"{PACKAGE_ROOT}/{path}"]
            if item["bytes"] != len(data) or item["sha256"] != sha256_bytes(data):
                raise IngressError(f"manifest inventory mismatch: {path}")
            if not isinstance(item["role"], str) or not item["role"]:
                raise IngressError(f"manifest role missing: {path}")
            if not isinstance(item["mediaType"], str) or not item["mediaType"]:
                raise IngressError(f"manifest media type missing: {path}")

        if manifest.get("payloadSetDigest") != inventory_digest(projected):
            raise IngressError("payload-set digest mismatch")
        evidence_entries = [item for item in projected if item["path"].startswith("payload/evidence/m0-a12/")]
        if manifest.get("evidenceSetDigest") != inventory_digest(evidence_entries):
            raise IngressError("evidence-set digest mismatch")
        evidence_paths = {
            item["path"].removeprefix("payload/evidence/m0-a12/")
            for item in evidence_entries
        }
        if not REQUIRED_M0_A12_PAYLOADS.issubset(evidence_paths):
            missing_evidence = sorted(REQUIRED_M0_A12_PAYLOADS - evidence_paths)
            raise IngressError("required M0-A12 evidence missing: " + ", ".join(missing_evidence))

        allowed = root / ALLOWED_SIGNERS_PATH
        _verify_signature(
            manifest_path,
            root / MANIFEST_SIGNATURE_PATH,
            allowed,
            "independent-observer-primary",
            INGRESS_NAMESPACE,
            "manifest.json",
        )

        approval_path = root / APPROVAL_PATH
        approval = load_object(approval_path)
        if approval.get("standard") != APPROVAL_STANDARD:
            raise IngressError("invalid operator-approval standard")
        if approval.get("sourceAuthorityHead") != M0_A12_HEAD:
            raise IngressError("operator approval is bound to the wrong M0-A12 head")
        if approval.get("evidenceSetDigest") != manifest.get("evidenceSetDigest"):
            raise IngressError("operator approval evidence-set digest mismatch")
        if approval.get("decision") != "approve-exact-binding-and-point-in-time-closure-attempt":
            raise IngressError("operator approval decision mismatch")
        if approval.get("irreversibleProviderActionsAcknowledged") is not True:
            raise IngressError("irreversible-provider-action acknowledgement absent")
        if approval.get("approvalDigest") != digest_document(approval, "approvalDigest"):
            raise IngressError("operator approval digest mismatch")
        for identity, rel in APPROVAL_SIGNATURES.items():
            _verify_signature(
                approval_path,
                root / rel,
                allowed,
                identity,
                APPROVAL_NAMESPACE,
                "operator-approval.json",
            )

        return {
            "standard": "EIGIIB-M0-A12-F1-PACKAGE-VERIFICATION-REPORT-1.0",
            "result": "verified-exact-closed-package",
            "archiveSha256": sha256_file(archive),
            "sourceAuthorityHead": M0_A12_HEAD,
            "manifestDigest": manifest["manifestDigest"],
            "payloadSetDigest": manifest["payloadSetDigest"],
            "evidenceSetDigest": manifest["evidenceSetDigest"],
            "entryCount": len(entries),
            "files": files,
        }


def _copy_payload(files: dict[str, bytes], destination: Path) -> int:
    payload_items = sorted(
        (path[len(PAYLOAD_PREFIX):], data)
        for path, data in files.items()
        if path.startswith(PAYLOAD_PREFIX)
    )
    for rel, _ in payload_items:
        target = destination / PurePosixPath(rel)
        if target.exists() or target.is_symlink():
            raise IngressError(f"destination path already exists: {rel}")
    for rel, data in payload_items:
        target = destination / PurePosixPath(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("xb") as handle:
                handle.write(data)
        except FileExistsError as exc:
            raise IngressError(f"destination path raced into existence: {rel}") from exc
    return len(payload_items)


def _write_receipt(destination: Path, report: dict[str, Any], result: str, verified_at: str) -> Path:
    receipt = {
        "standard": RECEIPT_STANDARD,
        "sourceAuthorityHead": M0_A12_HEAD,
        "archiveSha256": report["archiveSha256"],
        "manifestDigest": report["manifestDigest"],
        "payloadSetDigest": report["payloadSetDigest"],
        "evidenceSetDigest": report["evidenceSetDigest"],
        "entryCount": report["entryCount"],
        "result": result,
        "verifiedAt": verified_at,
        "receiptDigest": "",
    }
    receipt["receiptDigest"] = digest_document(receipt, "receiptDigest")
    path = destination / "evidence/m0-a12-f1/ingress-receipt.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise IngressError("ingress receipt already exists")
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def stage_package(archive: Path, destination: Path, result: str, verified_at: str) -> dict[str, Any]:
    report = verify_package(archive)
    destination.mkdir(parents=True, exist_ok=True)
    files = report.pop("files")
    copied = _copy_payload(files, destination)
    manifest_target = destination / "evidence/m0-a12-f1/package-manifest.json"
    signature_target = destination / "evidence/m0-a12-f1/package-manifest.json.sig"
    manifest_target.parent.mkdir(parents=True, exist_ok=True)
    for target in (manifest_target, signature_target):
        if target.exists() or target.is_symlink():
            raise IngressError(f"destination path already exists: {target.relative_to(destination).as_posix()}")
    manifest_target.write_bytes(files[MANIFEST_PATH])
    signature_target.write_bytes(files[MANIFEST_SIGNATURE_PATH])
    receipt_path = _write_receipt(destination, report, result, verified_at)
    return {
        **report,
        "result": result,
        "copiedEntryCount": copied,
        "receiptPath": receipt_path.as_posix(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("archive")

    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("archive")
    stage_parser.add_argument("destination")
    stage_parser.add_argument("--verified-at", default=None)

    bind_parser = subparsers.add_parser("bind")
    bind_parser.add_argument("archive")
    bind_parser.add_argument("repository_root")
    bind_parser.add_argument("--confirm", required=True)
    bind_parser.add_argument("--verified-at", default=None)

    args = parser.parse_args()
    try:
        if args.command == "verify":
            report = verify_package(Path(args.archive))
            report.pop("files", None)
        elif args.command == "stage":
            report = stage_package(
                Path(args.archive),
                Path(args.destination),
                "verified-and-staged-not-bound",
                args.verified_at or utc_now(),
            )
        else:
            if args.confirm != BIND_CONFIRMATION:
                raise IngressError("exact binding confirmation string is required")
            root = Path(args.repository_root)
            authority = root / "conformance/m0-a12-external-activation.json"
            if not authority.is_file():
                raise IngressError("target is not an M0-A12 authority tree")
            if (root / "evidence/m0-a12").exists() or (root / "evidence/m0-a12-f1").exists():
                raise IngressError("target evidence paths must not already exist")
            report = stage_package(
                Path(args.archive),
                root,
                "verified-and-bound",
                args.verified_at or utc_now(),
            )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except IngressError as exc:
        print(json.dumps({"standard": "EIGIIB-M0-A12-F1-INGRESS-ERROR-1.0", "result": "rejected", "error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
