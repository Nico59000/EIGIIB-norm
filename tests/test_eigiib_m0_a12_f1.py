from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = REPO_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from eigiib_m0_a12_f1_canonical import digest_document, inventory_digest
from eigiib_m0_a12_f1_check import evaluate, write_certificate

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:
    CRYPTO_AVAILABLE = False
else:
    CRYPTO_AVAILABLE = True
    from eigiib_m0_a12_signature import sign_file
    from eigiib_m0_a12_f1_ingress import BIND_CONFIRMATION, IngressError, stage_package, verify_package

M0_A12_HEAD = "e6661993924aed4d0185df48cf0b8587b2e0abf3"
PACKAGE_ROOT = "m0-a12-f1-package"


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def copy_authority(target: Path) -> None:
    freeze = json.loads((REPO_ROOT / "conformance/m0-a12-f1-authority-freeze.json").read_text(encoding="utf-8"))
    for item in freeze["authorities"]:
        source = REPO_ROOT / item["path"]
        destination = target / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    freeze_target = target / "conformance/m0-a12-f1-authority-freeze.json"
    freeze_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / "conformance/m0-a12-f1-authority-freeze.json", freeze_target)
    source = REPO_ROOT / "conformance/m0-a12-external-activation.json"
    destination = target / "conformance/m0-a12-external-activation.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def positive_m0_report(_: Path) -> dict:
    return {
        "standard": "EIGIIB-M0-A12-REPORT-1.0",
        "structural_result": "conformant",
        "activation_result": "point-in-time-external-activation-and-first-signed-observation-verified",
        "htntLabel": "T",
        "findings": [],
        "summary": {"e17Decision": "not-ready-for-adoption"},
    }


class M0A12F1BaselineTests(unittest.TestCase):
    def test_canonical_baseline_report(self) -> None:
        actual = evaluate(REPO_ROOT)
        expected = json.loads((REPO_ROOT / "tests/fixtures/m0-a12-f1/expected-baseline-report.json").read_text(encoding="utf-8"))
        self.assertEqual(expected, actual)
        self.assertEqual("NF", actual["htntLabel"])

    def test_require_closed_returns_two(self) -> None:
        result = subprocess.run(
            [sys.executable, "tools/eigiib_m0_a12_f1_check.py", ".", "--require-closed"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(2, result.returncode, result.stdout.decode())


@unittest.skipUnless(CRYPTO_AVAILABLE, "cryptography is required for M0-A12-F1 package tests")
class M0A12F1PackageTests(unittest.TestCase):
    maxDiff = None

    def make_key(self, root: Path, identity: str, key_id: str) -> tuple[Path, dict]:
        key = Ed25519PrivateKey.generate()
        path = root / f"{identity}.pem"
        path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        public_raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return path, {
            "identity": identity,
            "keyId": key_id,
            "algorithm": "ed25519",
            "publicKeyRawBase64": base64.b64encode(public_raw).decode("ascii"),
            "publicKeyDigest": hashlib.sha256(public_raw).hexdigest(),
            "validFrom": "2026-08-04T00:00:00Z",
            "validUntil": None,
            "purpose": "control-domain-attestation" if identity != "independent-observer-primary" else "preservation-observation",
        }

    def patch_signed_path(self, signature: Path, value: str) -> None:
        envelope = json.loads(signature.read_text(encoding="utf-8"))
        envelope["signedPayloadPath"] = value
        write_json(signature, envelope)

    def role_for(self, path: str) -> str:
        if path.endswith("allowed_signers.json"):
            return "allowed-signers"
        if "operator-approval" in path:
            return "binding-approval"
        if path.endswith(".sig"):
            return "detached-signature"
        return "m0-a12-evidence"

    def media_for(self, path: str) -> str:
        return "application/json"

    def make_package(self, directory: Path) -> Path:
        assembly = directory / "assembly"
        payload = assembly / PACKAGE_ROOT / "payload"
        evidence = payload / "evidence/m0-a12"
        f1 = payload / "evidence/m0-a12-f1"
        keys_dir = directory / "private"
        keys_dir.mkdir(parents=True)

        identities = [
            ("external-preservation-primary", "primary-key-1"),
            ("external-preservation-secondary", "secondary-key-1"),
            ("independent-observer-primary", "observer-key-1"),
        ]
        private: dict[str, Path] = {}
        signers = []
        for identity, key_id in identities:
            path, signer = self.make_key(keys_dir, identity, key_id)
            private[identity] = path
            signers.append(signer)
        write_json(evidence / "keys/allowed_signers.json", {
            "standard": "EIGIIB-M0-A12-ALLOWED-SIGNERS-1.0",
            "signers": signers,
        })

        required = [
            "control-domains/external-preservation-primary.json",
            "control-domains/external-preservation-primary.json.sig",
            "control-domains/external-preservation-secondary.json",
            "control-domains/external-preservation-secondary.json.sig",
            "control-domains/independent-observer-primary.json",
            "control-domains/independent-observer-primary.json.sig",
            "channels/immutable-channel-primary.json",
            "channels/immutable-channel-secondary.json",
            "diversity-matrix.json",
            "campaign-anchor.json",
            "observations/000001.json",
            "observations/000001.json.sig",
        ]
        for index, rel in enumerate(required, start=1):
            write_json(evidence / rel, {"fixture": rel, "index": index})

        evidence_entries = []
        for path in sorted(p for p in evidence.rglob("*") if p.is_file()):
            rel = "payload/" + path.relative_to(payload).as_posix()
            data = path.read_bytes()
            evidence_entries.append({
                "path": rel,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "role": self.role_for(rel),
                "mediaType": self.media_for(rel),
            })
        evidence_digest = inventory_digest(evidence_entries)

        approval = {
            "standard": "EIGIIB-M0-A12-F1-OPERATOR-APPROVAL-1.0",
            "sourceAuthorityHead": M0_A12_HEAD,
            "evidenceSetDigest": evidence_digest,
            "decision": "approve-exact-binding-and-point-in-time-closure-attempt",
            "irreversibleProviderActionsAcknowledged": True,
            "approvedAt": "2026-08-04T10:00:00Z",
            "providerResources": [
                {"channelId": "immutable-channel-primary", "providerResourceId": "arn:aws:s3:::fixture", "objectVersionId": "version-1"},
                {"channelId": "immutable-channel-secondary", "providerResourceId": "projects/_/buckets/fixture", "objectVersionId": "generation-1"},
            ],
            "approvalDigest": "",
        }
        approval["approvalDigest"] = digest_document(approval, "approvalDigest")
        approval_path = f1 / "operator-approval.json"
        write_json(approval_path, approval)
        suffixes = {
            "external-preservation-primary": ".primary.sig",
            "external-preservation-secondary": ".secondary.sig",
            "independent-observer-primary": ".observer.sig",
        }
        key_ids = {identity: key_id for identity, key_id in identities}
        for identity, suffix in suffixes.items():
            generated = sign_file(
                approval_path,
                private[identity],
                identity,
                key_ids[identity],
                "keys/allowed_signers.json",
                "eigiib-m0-a12-f1-approval@eigiib.example",
                "2026-08-04T10:01:00Z",
            )
            destination = Path(str(approval_path) + suffix)
            generated.replace(destination)
            self.patch_signed_path(destination, "operator-approval.json")

        all_entries = []
        payload_files = [p for p in payload.rglob("*") if p.is_file()]
        payload_files.sort(key=lambda p: ("payload/" + p.relative_to(payload).as_posix()))
        for path in payload_files:
            rel = "payload/" + path.relative_to(payload).as_posix()
            data = path.read_bytes()
            all_entries.append({
                "path": rel,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "role": self.role_for(rel),
                "mediaType": self.media_for(rel),
            })
        manifest = {
            "standard": "EIGIIB-M0-A12-F1-EVIDENCE-PACK-MANIFEST-1.0",
            "sourceAuthorityHead": M0_A12_HEAD,
            "packageRoot": PACKAGE_ROOT,
            "payloadPrefix": "payload/",
            "entries": all_entries,
            "payloadSetDigest": inventory_digest(all_entries),
            "evidenceSetDigest": evidence_digest,
            "manifestDigest": "",
        }
        manifest["manifestDigest"] = digest_document(manifest, "manifestDigest")
        manifest_path = assembly / PACKAGE_ROOT / "manifest.json"
        write_json(manifest_path, manifest)
        signature = sign_file(
            manifest_path,
            private["independent-observer-primary"],
            "independent-observer-primary",
            key_ids["independent-observer-primary"],
            "payload/evidence/m0-a12/keys/allowed_signers.json",
            "eigiib-m0-a12-f1-ingress@eigiib.example",
            "2026-08-04T10:02:00Z",
        )
        self.patch_signed_path(signature, "manifest.json")

        archive = directory / "evidence-package.tar"
        with tarfile.open(archive, "w") as handle:
            handle.add(assembly / PACKAGE_ROOT, arcname=PACKAGE_ROOT, recursive=True)
        return archive

    def mutate_tar(self, source: Path, destination: Path, mutate) -> None:
        with tarfile.open(source, "r") as reader, tarfile.open(destination, "w") as writer:
            for member in reader.getmembers():
                if member.isdir():
                    writer.addfile(member)
                    continue
                stream = reader.extractfile(member)
                data = stream.read() if stream else b""
                replacement = mutate(member, data)
                if replacement is None:
                    continue
                new_member, new_data = replacement
                writer.addfile(new_member, io.BytesIO(new_data))

    def test_verified_closed_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            report = verify_package(archive)
            self.assertEqual("verified-exact-closed-package", report["result"])
            self.assertGreaterEqual(report["entryCount"], 17)

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            bad = Path(tmp) / "bad.tar"
            shutil.copy2(archive, bad)
            with tarfile.open(bad, "a") as handle:
                data = b"escape"
                info = tarfile.TarInfo(f"{PACKAGE_ROOT}/../escape.txt")
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))
            with self.assertRaises(IngressError):
                verify_package(bad)

    def test_rejects_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            bad = Path(tmp) / "bad.tar"
            shutil.copy2(archive, bad)
            with tarfile.open(bad, "a") as handle:
                info = tarfile.TarInfo(f"{PACKAGE_ROOT}/payload/evidence/m0-a12/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                handle.addfile(info)
            with self.assertRaises(IngressError):
                verify_package(bad)

    def test_rejects_unlisted_extra_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            bad = Path(tmp) / "bad.tar"
            shutil.copy2(archive, bad)
            with tarfile.open(bad, "a") as handle:
                data = b"extra"
                info = tarfile.TarInfo(f"{PACKAGE_ROOT}/payload/evidence/m0-a12/extra.json")
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))
            with self.assertRaises(IngressError):
                verify_package(bad)

    def test_rejects_manifest_digest_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            bad = Path(tmp) / "bad.tar"
            def mutate(member, data):
                if member.name == f"{PACKAGE_ROOT}/manifest.json":
                    value = json.loads(data)
                    value["manifestDigest"] = "0" * 64
                    data = (json.dumps(value, indent=2) + "\n").encode()
                    member.size = len(data)
                return member, data
            self.mutate_tar(archive, bad, mutate)
            with self.assertRaises(IngressError):
                verify_package(bad)

    def test_rejects_wrong_source_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            bad = Path(tmp) / "bad.tar"
            def mutate(member, data):
                if member.name == f"{PACKAGE_ROOT}/manifest.json":
                    value = json.loads(data)
                    value["sourceAuthorityHead"] = "0" * 40
                    value["manifestDigest"] = digest_document(value, "manifestDigest")
                    data = (json.dumps(value, indent=2) + "\n").encode()
                    member.size = len(data)
                return member, data
            self.mutate_tar(archive, bad, mutate)
            with self.assertRaises(IngressError):
                verify_package(bad)

    def test_rejects_missing_approval_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            bad = Path(tmp) / "bad.tar"
            target = f"{PACKAGE_ROOT}/payload/evidence/m0-a12-f1/operator-approval.json.secondary.sig"
            self.mutate_tar(archive, bad, lambda member, data: None if member.name == target else (member, data))
            with self.assertRaises(IngressError):
                verify_package(bad)

    def test_bind_requires_exact_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.make_package(Path(tmp))
            result = subprocess.run(
                [sys.executable, str(TOOLS / "eigiib_m0_a12_f1_ingress.py"), "bind", str(archive), str(REPO_ROOT), "--confirm", "wrong"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(1, result.returncode)

    def prepare_bound_tree(self, directory: Path) -> Path:
        root = directory / "repo"
        copy_authority(root)
        archive = self.make_package(directory)
        report = stage_package(archive, root, "verified-and-bound", "2026-08-04T10:05:00Z")
        self.assertEqual("verified-and-bound", report["result"])
        return root

    def test_bound_tree_is_preclosure_nt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.prepare_bound_tree(Path(tmp))
            report = evaluate(root, positive_m0_report)
            self.assertEqual("conformant-preclosure", report["structural_result"])
            self.assertEqual("NT", report["htntLabel"])
            self.assertEqual([], report["findings"])

    def test_certificate_closes_in_t(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.prepare_bound_tree(Path(tmp))
            write_certificate(root, "2026-08-04T10:10:00Z", positive_m0_report)
            report = evaluate(root, positive_m0_report)
            self.assertEqual("conformant", report["structural_result"])
            self.assertEqual("point-in-time-m0-a12-activation-closed", report["closure_result"])
            self.assertEqual("T", report["htntLabel"])

    def test_certificate_digest_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.prepare_bound_tree(Path(tmp))
            certificate = write_certificate(root, "2026-08-04T10:10:00Z", positive_m0_report)
            value = json.loads(certificate.read_text(encoding="utf-8"))
            value["certificateDigest"] = "0" * 64
            write_json(certificate, value)
            report = evaluate(root, positive_m0_report)
            self.assertIn("M0A12F1.CERTIFICATE.DIGEST", report["findings"])

    def test_staged_receipt_cannot_close(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.prepare_bound_tree(Path(tmp))
            receipt = root / "evidence/m0-a12-f1/ingress-receipt.json"
            value = json.loads(receipt.read_text(encoding="utf-8"))
            value["result"] = "verified-and-staged-not-bound"
            value["receiptDigest"] = digest_document(value, "receiptDigest")
            write_json(receipt, value)
            report = evaluate(root, positive_m0_report)
            self.assertIn("M0A12F1.RECEIPT.RESULT", report["findings"])

    def test_extra_bound_m0_a12_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.prepare_bound_tree(Path(tmp))
            write_json(root / "evidence/m0-a12/undeclared.json", {"unexpected": True})
            report = evaluate(root, positive_m0_report)
            self.assertIn("M0A12F1.MANIFEST.M0A12_CLOSED_SET", report["findings"])


if __name__ == "__main__":
    unittest.main()
