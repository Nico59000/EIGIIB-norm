from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = REPO_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from eigiib_m0_a12_canonical import digest_document

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ModuleNotFoundError:
    CRYPTOGRAPHY_AVAILABLE = False
else:
    from eigiib_m0_a12_check import (
        BUNDLE_BYTES,
        BUNDLE_SHA256,
        CHANNELS,
        DIMENSIONS,
        DOMAINS,
        FREEZE_PATH,
        M0_A11_PATH,
        evaluate,
    )
    from eigiib_m0_a12_signature import DEFAULT_NAMESPACE, sign_file

    CRYPTOGRAPHY_AVAILABLE = True

MANIFEST_SHA = "25c04438df49d7261cf9814142dc0dd575b278ba65e05bc244b13b35d16407a9"
SIG_SHA = "90925a270871949faf2079eb74321200b0f2eae873a4bc22c9cfac6ccee0a4e4"
PUB_SHA = "27116e2e7771cc300b2d2acbc205fd0992c23b8ebec4fe5b5b58023f0aa5382e"


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def copy_authority(target: Path) -> None:
    freeze = json.loads((REPO_ROOT / FREEZE_PATH).read_text(encoding="utf-8"))
    paths = [item["path"] for item in freeze["authorities"]]
    paths.extend([FREEZE_PATH, M0_A11_PATH])
    for rel in paths:
        source = REPO_ROOT / rel
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def make_key(directory: Path, identity: str, key_id: str) -> tuple[Path, dict]:
    key = Ed25519PrivateKey.generate()
    private_path = directory / f"{identity}.pem"
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signer = {
        "identity": identity,
        "keyId": key_id,
        "algorithm": "ed25519",
        "publicKeyRawBase64": base64.b64encode(public_raw).decode("ascii"),
        "publicKeyDigest": hashlib.sha256(public_raw).hexdigest(),
        "validFrom": "2026-08-04T00:00:00Z",
        "validUntil": None,
        "purpose": "preservation-observation" if identity == "independent-observer-primary" else "control-domain-attestation",
    }
    return private_path, signer


def add_digest(value: dict, field: str) -> dict:
    value[field] = ""
    value[field] = digest_document(value, field)
    return value


def build_complete_synthetic_evidence(root: Path) -> None:
    evidence = root / "evidence/m0-a12"
    keys = evidence / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    private = root / ".test-private"
    private.mkdir(parents=True, exist_ok=True)

    identities = [
        "external-preservation-primary",
        "external-preservation-secondary",
        "independent-observer-primary",
    ]
    key_map: dict[str, Path] = {}
    key_ids: dict[str, str] = {}
    signer_records: list[dict] = []
    for index, identity in enumerate(identities, 1):
        key_id = f"key-{index}"
        key, signer = make_key(private, identity, key_id)
        key_map[identity] = key
        key_ids[identity] = key_id
        signer_records.append(signer)
    write_json(keys / "allowed_signers.json", {
        "standard": "EIGIIB-M0-A12-ALLOWED-SIGNERS-1.0",
        "signers": signer_records,
    })

    domain_values = {
        "external-preservation-primary": ("preservation-custodian","Amazon Web Services","Amazon S3","aws-account-a"),
        "external-preservation-secondary": ("preservation-custodian","Google Cloud","Cloud Storage","gcp-project-b"),
        "independent-observer-primary": ("independent-observer","GitLab","Scheduled CI","gitlab-account-c"),
    }
    for index, identity in enumerate(identities, 1):
        role, provider, service, tenant = domain_values[identity]
        doc = {
            "standard":"EIGIIB-M0-A12-CONTROL-DOMAIN-ATTESTATION-1.0",
            "domainId":identity,
            "role":role,
            "providerOperator":provider,
            "service":service,
            "tenantAccountId":tenant,
            "identityRoot":f"identity-root-{index}",
            "privilegedAdministratorSet":[f"admin-set-{index}"],
            "billingAuthority":f"billing-authority-{index}",
            "credentialStore":f"credential-store-{index}",
            "executionPlane":f"execution-plane-{index}",
            "regionOrFailureDomain":[f"failure-domain-{index}"],
            "auditLogCustody":f"audit-custody-{index}",
            "issuedAt":"2026-08-04T01:00:00Z",
            "evidenceRefs":[f"raw/{identity}-account.json"],
            "signerKeyId":key_ids[identity],
            "payloadDigest":"",
            "claimBoundary":"bounded-point-in-time-control-domain-attestation",
        }
        add_digest(doc, "payloadDigest")
        path = evidence / f"control-domains/{identity}.json"
        write_json(path, doc)
        sign_file(path, key_map[identity], identity, key_ids[identity], "keys/allowed_signers.json", DEFAULT_NAMESPACE, "2026-08-04T01:00:00Z")

    common_artifact = {
        "name":"eigiib-e16-1.0-stable-bundle.tar.gz",
        "bytes":BUNDLE_BYTES,
        "sha256":BUNDLE_SHA256,
        "manifestSha256":MANIFEST_SHA,
        "signatureSha256":SIG_SHA,
        "publicKeySha256":PUB_SHA,
    }
    channels = {
        "immutable-channel-primary": {
            "domain":"external-preservation-primary",
            "profile":"aws-s3-object-lock-compliance",
            "resource":"arn:aws:s3:::eigiib-test-primary",
            "endpoint":"s3://eigiib-test-primary/eigiib-e16-1.0-stable-bundle.tar.gz",
            "version":"aws-version-1",
            "mode":"AWS-COMPLIANCE",
        },
        "immutable-channel-secondary": {
            "domain":"external-preservation-secondary",
            "profile":"gcp-cloud-storage-bucket-lock",
            "resource":"//storage.googleapis.com/projects/_/buckets/eigiib-test-secondary",
            "endpoint":"gs://eigiib-test-secondary/eigiib-e16-1.0-stable-bundle.tar.gz",
            "version":"gcs-generation-1",
            "mode":"GCS-LOCKED-BUCKET-RETENTION",
        },
    }
    for channel, values in channels.items():
        doc = {
            "standard":"EIGIIB-M0-A12-CHANNEL-EVIDENCE-1.0",
            "channelId":channel,
            "controlDomainId":values["domain"],
            "providerProfile":values["profile"],
            "providerResourceId":values["resource"],
            "endpoint":values["endpoint"],
            "objectVersionId":values["version"],
            "artifact":common_artifact,
            "retention":{
                "mode":values["mode"],
                "policyState":"applied-and-readback-verified",
                "lockEffectiveAt":"2026-08-04T01:00:00Z",
                "retainUntil":"2026-09-03T01:00:00Z",
                "minimumWindowSeconds":2592000,
                "readbackEvidenceRef":f"raw/{channel}-retention.json",
            },
            "deleteDenials":[
                {
                    "principalClass":"authorized-deleter",
                    "operation":"delete-specific-object-version",
                    "result":"denied",
                    "denialAttributedToRetention":True,
                    "objectStillPresent":True,
                    "evidenceRef":f"raw/{channel}-delete-authorized.log",
                },
                {
                    "principalClass":"privileged-administrator",
                    "operation":"delete-specific-object-version",
                    "result":"denied",
                    "denialAttributedToRetention":True,
                    "objectStillPresent":True,
                    "evidenceRef":f"raw/{channel}-delete-privileged.log",
                },
            ],
            "auditEvidenceRefs":[f"raw/{channel}-audit.json"],
            "exactReadback":{
                "bytes":BUNDLE_BYTES,
                "sha256":BUNDLE_SHA256,
                "readAt":"2026-08-04T01:15:00Z",
                "readerDomainId":"independent-observer-primary",
                "evidenceRef":f"raw/{channel}-readback.json",
            },
            "capturedAt":"2026-08-04T01:10:00Z",
            "payloadDigest":"",
        }
        add_digest(doc, "payloadDigest")
        write_json(evidence / f"channels/{channel}.json", doc)

    comparisons = []
    for left, right in itertools.combinations(DOMAINS, 2):
        for dimension in DIMENSIONS:
            comparisons.append({
                "left":left,
                "right":right,
                "dimension":dimension,
                "result":"distinct",
                "evidenceRefs":[f"raw/diversity/{left}--{right}--{dimension}.json"],
            })
    matrix = {
        "standard":"EIGIIB-M0-A12-DIVERSITY-MATRIX-1.0",
        "domains":DOMAINS,
        "dimensions":DIMENSIONS,
        "comparisons":comparisons,
        "decision":"required-independence-established-for-point-in-time-activation",
        "payloadDigest":"",
    }
    add_digest(matrix, "payloadDigest")
    write_json(evidence / "diversity-matrix.json", matrix)

    anchor = {
        "standard":"EIGIIB-M0-A12-CAMPAIGN-ANCHOR-1.0",
        "campaignId":"eigiib-m0-a11-external-preservation-observation-v1",
        "activatedAt":"2026-08-04T01:20:00Z",
        "sourceM0A12Head":"a"*40,
        "observerDomainId":"independent-observer-primary",
        "observerKeyId":"key-3",
        "expectedChannelIds":CHANNELS,
        "initialObjectVersionIds":{
            "immutable-channel-primary":"aws-version-1",
            "immutable-channel-secondary":"gcs-generation-1",
        },
        "schedule":{"cadenceSeconds":86400,"graceSeconds":21600,"lapseAfterSeconds":172800,"clock":"utc-rfc3339"},
        "approvalEvidenceRefs":["raw/campaign-approval.json"],
        "payloadDigest":"",
    }
    add_digest(anchor, "payloadDigest")
    write_json(evidence / "campaign-anchor.json", anchor)

    observation = {
        "standard":"EIGIIB-M0-A12-OBSERVATION-1.0",
        "campaignId":"eigiib-m0-a11-external-preservation-observation-v1",
        "sequence":1,
        "observedAt":"2026-08-04T01:30:00Z",
        "previousObservationDigest":None,
        "observerDomainId":"independent-observer-primary",
        "observerKeyId":"key-3",
        "channels":[
            {
                "channelId":"immutable-channel-primary",
                "providerResourceId":channels["immutable-channel-primary"]["resource"],
                "objectVersionId":"aws-version-1",
                "readbackBytes":BUNDLE_BYTES,
                "readbackSha256":BUNDLE_SHA256,
                "retentionState":"applied-and-readback-verified",
                "result":"exact-and-retained",
                "evidenceRefs":["raw/primary-observer-readback.json"],
            },
            {
                "channelId":"immutable-channel-secondary",
                "providerResourceId":channels["immutable-channel-secondary"]["resource"],
                "objectVersionId":"gcs-generation-1",
                "readbackBytes":BUNDLE_BYTES,
                "readbackSha256":BUNDLE_SHA256,
                "retentionState":"applied-and-readback-verified",
                "result":"exact-and-retained",
                "evidenceRefs":["raw/secondary-observer-readback.json"],
            },
        ],
        "observationDigest":"",
    }
    add_digest(observation, "observationDigest")
    observation_path = evidence / "observations/000001.json"
    write_json(observation_path, observation)
    sign_file(observation_path, key_map["independent-observer-primary"], "independent-observer-primary", key_ids["independent-observer-primary"], "keys/allowed_signers.json", DEFAULT_NAMESPACE, "2026-08-04T01:30:00Z")


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography dependency is installed only by the dedicated M0-A12 workflow")
class M0A12Tests(unittest.TestCase):
    maxDiff = None

    def test_positive_preactivation_authority(self) -> None:
        report = evaluate(REPO_ROOT)
        expected = json.loads((REPO_ROOT / "tests/fixtures/m0-a12/expected-preactivation-report.json").read_text(encoding="utf-8"))
        self.assertEqual(expected, report)
        self.assertEqual("NF", report["htntLabel"])

    def test_require_activated_returns_two(self) -> None:
        result = subprocess.run(
            [sys.executable, "tools/eigiib_m0_a12_check.py", ".", "--require-activated"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(2, result.returncode, result.stdout.decode())

    def mutation(self, rel: str, mutate) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            copy_authority(target)
            path = target / rel
            value = json.loads(path.read_text(encoding="utf-8"))
            mutate(value)
            write_json(path, value)
            return evaluate(target)

    def test_m0_a11_head_substitution_is_rejected(self) -> None:
        report = self.mutation("conformance/m0-a12-external-activation.json", lambda v: v["source"].__setitem__("m0A11Head", "0"*40))
        self.assertIn("M0A12.SOURCE.M0A11", report["findings"])

    def test_premature_htnt_promotion_is_rejected(self) -> None:
        report = self.mutation("conformance/m0-a12-external-activation.json", lambda v: v["typedDecisionProtocol"].__setitem__("currentLabel", "T"))
        self.assertIn("M0A12.HTNT.CURRENT", report["findings"])

    def test_premature_resource_binding_is_rejected(self) -> None:
        def mutate(v):
            v["profiles"][0]["resourceBindingState"] = "bound"
        report = self.mutation("conformance/m0-a12-provider-profiles.json", mutate)
        self.assertTrue(any(x.startswith("M0A12.PROFILE.PREMATURE_RESOURCE") for x in report["findings"]))

    def test_fake_ledger_entry_is_rejected(self) -> None:
        def mutate(v):
            v["entries"] = [{"fake":True}]
        report = self.mutation("conformance/m0-a12-evidence-ledger.json", mutate)
        self.assertIn("M0A12.LEDGER.PREMATURE", report["findings"])

    def test_variable_context_is_rejected(self) -> None:
        report = self.mutation("conformance/m0-a12-htnt-decision-protocol.json", lambda v: v.__setitem__("fixedContext", False))
        self.assertIn("M0A12.PROTOCOL.CONTEXT", report["findings"])

    def test_partial_external_evidence_is_nt_and_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            copy_authority(target)
            (target / "evidence/m0-a12").mkdir(parents=True)
            report = evaluate(target)
            self.assertEqual("NT", report["htntLabel"])
            self.assertEqual("invalid-or-conflicting-evidence", report["activation_result"])
            self.assertTrue(any(x.startswith("M0A12.EVIDENCE.MISSING") for x in report["findings"]))

    def with_complete_evidence(self, mutate=None) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            copy_authority(target)
            build_complete_synthetic_evidence(target)
            if mutate:
                mutate(target)
            return evaluate(target)

    def test_complete_synthetic_conformance_vector_reaches_t(self) -> None:
        report = self.with_complete_evidence()
        self.assertEqual([], report["findings"])
        self.assertEqual("T", report["htntLabel"])
        self.assertEqual("point-in-time-external-activation-and-first-signed-observation-verified", report["activation_result"])

    def test_observation_digest_substitution_is_rejected(self) -> None:
        def mutate(root):
            path = root / "evidence/m0-a12/observations/000001.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["observationDigest"] = "0"*64
            write_json(path, value)
        report = self.with_complete_evidence(mutate)
        self.assertIn("M0A12.OBS.DIGEST", report["findings"])

    def test_signature_substitution_is_rejected(self) -> None:
        def mutate(root):
            path = root / "evidence/m0-a12/observations/000001.json.sig"
            path.write_text("not a signature\n", encoding="utf-8")
        report = self.with_complete_evidence(mutate)
        self.assertTrue(any(x.startswith("M0A12.OBS.SIGNATURE") for x in report["findings"]))

    def test_shared_tenant_is_rejected(self) -> None:
        def mutate(root):
            primary = root / "evidence/m0-a12/control-domains/external-preservation-primary.json"
            secondary = root / "evidence/m0-a12/control-domains/external-preservation-secondary.json"
            p = json.loads(primary.read_text(encoding="utf-8"))
            s = json.loads(secondary.read_text(encoding="utf-8"))
            s["tenantAccountId"] = p["tenantAccountId"]
            add_digest(s, "payloadDigest")
            write_json(secondary, s)
        report = self.with_complete_evidence(mutate)
        self.assertTrue(any("tenantAccountId" in x for x in report["findings"]))

    def test_observation_missing_channel_is_rejected(self) -> None:
        def mutate(root):
            path = root / "evidence/m0-a12/observations/000001.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["channels"] = value["channels"][:1]
            add_digest(value, "observationDigest")
            write_json(path, value)
        report = self.with_complete_evidence(mutate)
        self.assertIn("M0A12.OBS.CHANNEL_SET", report["findings"])

    def test_delete_denial_must_be_retention_attributed(self) -> None:
        def mutate(root):
            path = root / "evidence/m0-a12/channels/immutable-channel-primary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["deleteDenials"][0]["denialAttributedToRetention"] = False
            add_digest(value, "payloadDigest")
            write_json(path, value)
        report = self.with_complete_evidence(mutate)
        self.assertIn("M0A12.CHANNEL.DELETE_DENIAL_DETAIL:immutable-channel-primary", report["findings"])

    def test_diversity_shared_cell_is_rejected(self) -> None:
        def mutate(root):
            path = root / "evidence/m0-a12/diversity-matrix.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["comparisons"][0]["result"] = "shared"
            add_digest(value, "payloadDigest")
            write_json(path, value)
        report = self.with_complete_evidence(mutate)
        self.assertIn("M0A12.DIVERSITY.NOT_DISTINCT", report["findings"])

    def test_freeze_digest_substitution_is_rejected(self) -> None:
        def mutate(v):
            v["authorities"][0]["sha256"] = "0"*64
        report = self.mutation(FREEZE_PATH, mutate)
        self.assertTrue(any(x.startswith("M0A12.FREEZE.SHA256") for x in report["findings"]))

    def test_provider_scripts_are_syntax_valid(self) -> None:
        if os.name == "nt":
            self.skipTest("provider shell syntax is checked by the workflow Git Bash step")
        for rel in [
            "tools/m0_a12/aws_s3_object_lock_activate.sh",
            "tools/m0_a12/gcs_bucket_lock_activate.sh",
        ]:
            result = subprocess.run(["bash", "-n", rel], cwd=REPO_ROOT, check=False)
            self.assertEqual(0, result.returncode, rel)


if __name__ == "__main__":
    unittest.main()
