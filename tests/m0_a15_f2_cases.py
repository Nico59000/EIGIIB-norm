import argparse
import base64
import json
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_m0_a15_f1_canonical import canonical_bytes, digest_hex
from eigiib_m0_a15_f1_check import evaluate as evaluate_f1
from eigiib_m0_a15_f1_historical_a14 import verify_a14_replay
from eigiib_m0_a15_f2_replay import F1_HEAD, F1_TREE, MEDIA_TYPE
from m0_a15_f1_cases import CaseBuilder

A13_HEAD = "d096b9fbf68cead15a3a9eb7bf4cff1493a0aa45"
COLLEGES = (
    "normative-authority-college",
    "operational-governance-college",
    "independent-verification-college",
)


def h(character):
    return (str(character) * 64)[:64]


def approvals(record_digest, prefix="a"):
    return [
        {
            "collegeId": college,
            "approverId": f"{prefix}-{college_index}-{member_index}",
            "controlDomainId": f"{prefix}-domain-{college_index}-{member_index}",
            "recordDigest": record_digest,
        }
        for college_index, college in enumerate(COLLEGES)
        for member_index in range(4)
    ]


def snapshot(digest_character="a"):
    return {
        "snapshotDigest": h(digest_character),
        "unknownControlOverlap": False,
        "colleges": [
            {
                "id": college,
                "members": 5,
                "threshold": 4,
                "distinctControlDomains": 5,
                "memberIds": [f"g-{college_index}-m{index}" for index in range(5)],
                "controlDomainIds": [f"g-{college_index}-d{index}" for index in range(5)],
            }
            for college_index, college in enumerate(COLLEGES)
        ],
    }


def cycle(sequence, predecessor, successor, issued, executed, closed, governance, revoked=False):
    request_digest = h(sequence + 2)
    authority_digest = h(sequence + 5)
    revocations = []
    writes = [{"path": f"conformance/c{sequence}.json", "at": issued.replace("00:00:00", "01:00:00")}]
    if revoked:
        subset = [
            {
                "collegeId": COLLEGES[0],
                "approverId": f"r-{index}",
                "controlDomainId": f"rd-{index}",
                "recordDigest": request_digest,
            }
            for index in range(4)
        ]
        revocations = [{
            "revocationId": f"rev-{sequence}",
            "collegeId": COLLEGES[0],
            "requestDigest": request_digest,
            "effectiveAt": issued.replace("00:00:00", "02:00:00"),
            "approvals": subset,
            "outcome": "revoked-and-refrozen",
        }]
    return {
        "sequence": sequence,
        "maintenanceEventId": f"event-{sequence}",
        "maintenanceClass": "normative-correction",
        "predecessorRefreezeDigest": predecessor,
        "successorRefreezeDigest": successor,
        "requestDigest": request_digest,
        "reopeningAuthorityDigest": authority_digest,
        "issuedAt": issued,
        "expiresAt": issued.replace("00:00:00", "23:00:00"),
        "executedAt": executed,
        "closedAt": closed,
        "affectedPaths": [f"conformance/c{sequence}.json"],
        "implementedPaths": [f"conformance/c{sequence}.json"],
        "approvals": approvals(request_digest, f"c{sequence}"),
        "governanceSnapshot": governance,
        "governanceTransition": None,
        "revocationEvents": revocations,
        "authorizedWrites": writes,
        "supersessionRecordValid": True,
        "independentVerificationValid": True,
        "workflowConclusions": ["success", "success", "success"],
        "refreezeManifestValid": True,
        "independentRefreezeReadbackValid": True,
        "closureCertificateValid": True,
    }


def complete_a14_case():
    governance = snapshot()
    initial = h("0")
    return {
        "a13Decision": "verified",
        "a13Head": A13_HEAD,
        "a13ClosureCertificateValid": True,
        "initialRefreezeDigest": initial,
        "cycles": [
            cycle(1, initial, h("1"), "2026-01-01T00:00:00Z", "2026-01-01T03:00:00Z", "2026-01-02T00:00:00Z", governance, True),
            cycle(2, h("1"), h("2"), "2026-01-15T00:00:00Z", "2026-01-15T03:00:00Z", "2026-01-16T00:00:00Z", governance),
            cycle(3, h("2"), h("3"), "2026-02-01T00:00:00Z", "2026-02-01T03:00:00Z", "2026-02-02T00:00:00Z", governance),
        ],
        "continuityCertificateValid": True,
    }


def key(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public_b64(private_key):
    return base64.b64encode(private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )).decode()


def sign(private_key, key_id, payload):
    return {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "keyId": key_id,
            "value": base64.b64encode(private_key.sign(canonical_bytes(payload))).decode(),
        },
    }


def profile(principal_id, role, seed, randomize=False):
    private = Ed25519PrivateKey.generate() if randomize else key(seed)
    return private, {
        "principalId": principal_id,
        "role": role,
        "controlDomainId": f"{principal_id}-domain",
        "identityRoot": f"{principal_id}-root",
        "providerOperator": f"{principal_id}-provider",
        "networkPath": f"{principal_id}-network",
        "implementation": f"{principal_id}-implementation",
        "keyId": f"{principal_id}-key",
        "algorithm": "ed25519",
        "publicKey": public_b64(private),
    }


def build_valid_history(root=ROOT, randomize=False):
    if randomize:
        with patch("m0_a15_f1_cases.key", side_effect=lambda _: Ed25519PrivateKey.generate()):
            builder = CaseBuilder()
    else:
        builder = CaseBuilder()
    history = builder.build()
    a14_case = complete_a14_case()
    a14_result = verify_a14_replay(root, a14_case)
    if not a14_result.get("verified"):
        raise RuntimeError(f"exact A14 replay did not verify: {a14_result.get('errors')}")
    a14_digest = a14_result["replayDigest"]
    a14_time = history["a14Replay"]["witnessEndorsements"][0]["payload"]["signedAt"]
    history["a14Replay"] = {
        "case": a14_case,
        "witnessEndorsements": builder.endorse("a14-continuity-replay", a14_digest, a14_time),
    }
    certificate = history["longTermCertificate"]
    certificate["payload"]["a14ReplayDigest"] = a14_digest
    certificate_digest = digest_hex(certificate["payload"])
    certificate_time = certificate["witnessEndorsements"][0]["payload"]["signedAt"]
    last_checkpoint = certificate["payload"]["lastCheckpointDigest"]
    certificate["witnessEndorsements"] = builder.endorse(
        "long-term-certificate", certificate_digest, certificate_time
    )
    certificate["readbacks"] = [
        builder.readback("observer-1", "long-term-certificate", certificate_digest, last_checkpoint, "long-term-certificate", None, certificate_time),
        builder.readback("observer-2", "long-term-certificate", certificate_digest, last_checkpoint, "long-term-certificate", None, certificate_time),
    ]
    return history


def _f1_report(root, history):
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "history.json"
        path.write_text(json.dumps(history, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        report = evaluate_f1(root, path)
    if report.get("htntLabel") != "T":
        raise RuntimeError(f"F1 did not reach T: {report}")
    return report


def build_activation_package(
    root=ROOT,
    randomize=False,
    carrier_locator="https://registry-a.example.org/eigiib/m0-a15-f2/history-2026q1.json",
):
    history = build_valid_history(root, randomize=randomize)
    history_digest = digest_hex(history)
    history_bytes = len(canonical_bytes(history))
    f1_report = _f1_report(root, history)
    f1_report_digest = digest_hex(f1_report)

    publisher_private, publisher = profile("external-publisher", "publisher", 21, randomize)
    observer_pairs = [profile(f"external-observer-{index}", "observer", 21 + index, randomize) for index in (1, 2)]
    authority_private, authority = profile("activation-authority", "activation-authority", 24, randomize)
    witness_pairs = [profile(f"activation-witness-{index}", "activation-witness", 24 + index, randomize) for index in range(1, 5)]

    carrier = {
        "carrierId": "external-registry-history-2026q1",
        "locator": carrier_locator,
        "retrievedAt": "2026-04-02T00:00:00Z",
        "mediaType": MEDIA_TYPE,
        "contentLength": history_bytes,
    }
    ingress_payload = {
        "recordType": "external-history-ingress",
        "sourceF1Head": F1_HEAD,
        "sourceF1Tree": F1_TREE,
        "historyDigest": history_digest,
        "historyBytes": history_bytes,
        "carrierId": carrier["carrierId"],
        "carrierLocator": carrier["locator"],
        "retrievedAt": carrier["retrievedAt"],
        "publisherId": publisher["principalId"],
    }
    ingress_receipt = sign(publisher_private, publisher["keyId"], ingress_payload)
    ingress_receipt_digest = digest_hex(ingress_payload)
    ingress_readbacks = []
    for index, (private, observer) in enumerate(observer_pairs, 5):
        payload = {
            "recordType": "external-history-readback",
            "observerId": observer["principalId"],
            "controlDomainId": observer["controlDomainId"],
            "historyDigest": history_digest,
            "ingressReceiptDigest": ingress_receipt_digest,
            "carrierId": carrier["carrierId"],
            "carrierLocator": carrier["locator"],
            "observedAt": f"2026-04-02T00:0{index}:00Z",
        }
        ingress_readbacks.append(sign(private, observer["keyId"], payload))
    readback_set_digest = digest_hex(sorted(digest_hex(envelope) for envelope in ingress_readbacks))

    activation_payload = {
        "recordType": "point-in-time-activation",
        "sourceF1Head": F1_HEAD,
        "sourceF1Tree": F1_TREE,
        "historyDigest": history_digest,
        "f1ReportDigest": f1_report_digest,
        "ingressReceiptDigest": ingress_receipt_digest,
        "ingressReadbackSetDigest": readback_set_digest,
        "activationSequence": 1,
        "previousActivationDigest": None,
        "activationNonce": h("e"),
        "activatedAt": "2026-04-02T00:15:00Z",
        "validUntil": "2026-04-02T01:00:00Z",
        "decision": "m0-a15-f2-t-closure",
    }
    activation_envelope = sign(authority_private, authority["keyId"], activation_payload)
    activation_digest = digest_hex(activation_payload)
    endorsements = []
    for private, witness in witness_pairs[:3]:
        payload = {
            "recordType": "point-in-time-activation-endorsement",
            "witnessId": witness["principalId"],
            "controlDomainId": witness["controlDomainId"],
            "activationDigest": activation_digest,
            "signedAt": "2026-04-02T00:20:00Z",
        }
        endorsements.append(sign(private, witness["keyId"], payload))
    activation_readbacks = []
    for private, observer in observer_pairs:
        payload = {
            "recordType": "point-in-time-activation-readback",
            "observerId": observer["principalId"],
            "controlDomainId": observer["controlDomainId"],
            "activationDigest": activation_digest,
            "historyDigest": history_digest,
            "f1ReportDigest": f1_report_digest,
            "scope": "published-point-in-time-activation",
            "observedAt": "2026-04-02T00:25:00Z",
        }
        activation_readbacks.append(sign(private, observer["keyId"], payload))

    package = {
        "standard": "EIGIIB-M0-A15-F2-ACTIVATION-PACKAGE-1.0",
        "source": {"f1Head": F1_HEAD, "f1Tree": F1_TREE},
        "evidenceClass": "external-authenticated-history",
        "history": history,
        "historyDigest": history_digest,
        "carrier": carrier,
        "publisher": publisher,
        "ingressReceipt": ingress_receipt,
        "observers": [observer for _, observer in observer_pairs],
        "ingressReadbacks": ingress_readbacks,
        "activationAuthority": authority,
        "activationWitnesses": [witness for _, witness in witness_pairs],
        "activation": {
            "envelope": activation_envelope,
            "witnessEndorsements": endorsements,
            "readbacks": activation_readbacks,
        },
    }
    return package, "2026-04-02T00:30:00Z", f1_report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--at-output", required=True)
    parser.add_argument("--history-output")
    parser.add_argument("--carrier-locator", default="https://registry-a.example.org/eigiib/m0-a15-f2/history-2026q1.json")
    parser.add_argument("--randomize", action="store_true")
    args = parser.parse_args()
    package, evaluation_at, _ = build_activation_package(
        ROOT, randomize=args.randomize, carrier_locator=args.carrier_locator
    )
    Path(args.output).write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    Path(args.at_output).write_text(evaluation_at + "\n", encoding="utf-8")
    if args.history_output:
        Path(args.history_output).write_text(json.dumps(package["history"], indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
