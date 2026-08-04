#!/usr/bin/env python3
"""External history ingress and point-in-time activation replay for M0-A15-F2."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from eigiib_m0_a15_f1_canonical import canonical_bytes, digest_hex, is_hex, parse_time
from eigiib_m0_a15_f1_check import evaluate as evaluate_f1
from eigiib_m0_a15_f1_crypto import verify_envelope

F1_HEAD = "b66ba8d5b11ce4e9d30d5fdb70fb982db3e26095"
F1_TREE = "9c2ded5aedbf5c22d311461ad7ee42d8315f8763"
MEDIA_TYPE = "application/vnd.eigiib.m0-a15-f1-history+json"
MAX_INGRESS_TO_ACTIVATION_SECONDS = 86400
MAX_ACTIVATION_WINDOW_SECONDS = 3600
MIN_INGRESS_OBSERVERS = 2
MIN_ACTIVATION_WITNESSES = 3
MIN_ACTIVATION_READBACKS = 2

PACKAGE_KEYS = {
    "standard", "source", "evidenceClass", "history", "historyDigest", "carrier",
    "publisher", "ingressReceipt", "observers", "ingressReadbacks",
    "activationAuthority", "activationWitnesses", "activation",
}
SOURCE_KEYS = {"f1Head", "f1Tree"}
CARRIER_KEYS = {"carrierId", "locator", "retrievedAt", "mediaType", "contentLength"}
PROFILE_KEYS = {
    "principalId", "role", "controlDomainId", "identityRoot", "providerOperator",
    "networkPath", "implementation", "keyId", "algorithm", "publicKey",
}
ACTIVATION_KEYS = {"envelope", "witnessEndorsements", "readbacks"}
INGRESS_PAYLOAD_KEYS = {
    "recordType", "sourceF1Head", "sourceF1Tree", "historyDigest", "historyBytes",
    "carrierId", "carrierLocator", "retrievedAt", "publisherId",
}
INGRESS_READBACK_KEYS = {
    "recordType", "observerId", "controlDomainId", "historyDigest",
    "ingressReceiptDigest", "carrierId", "carrierLocator", "observedAt",
}
ACTIVATION_PAYLOAD_KEYS = {
    "recordType", "sourceF1Head", "sourceF1Tree", "historyDigest", "f1ReportDigest",
    "ingressReceiptDigest", "ingressReadbackSetDigest", "activationSequence",
    "previousActivationDigest", "activationNonce", "activatedAt", "validUntil", "decision",
}
ACTIVATION_ENDORSEMENT_KEYS = {
    "recordType", "witnessId", "controlDomainId", "activationDigest", "signedAt",
}
ACTIVATION_READBACK_KEYS = {
    "recordType", "observerId", "controlDomainId", "activationDigest", "historyDigest",
    "f1ReportDigest", "scope", "observedAt",
}


def _shape(value: Any, keys: set[str], prefix: str, errors: list[str]) -> bool:
    if not isinstance(value, dict) or set(value) != keys:
        errors.append(f"{prefix}-shape-invalid")
        return False
    return True


def _valid_external_locator(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    return (
        parsed.scheme == "https"
        and bool(host)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and host not in {"localhost", "127.0.0.1", "::1"}
        and not host.endswith(".invalid")
        and not host.endswith(".localhost")
    )


def _profile_map(
    profiles: Any,
    role: str,
    minimum: int,
    prefix: str,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(profiles, list) or len(profiles) < minimum:
        errors.append(f"{prefix}-count-insufficient")
        return result
    for index, profile in enumerate(profiles, 1):
        item_prefix = f"{prefix}-{index}"
        if not _shape(profile, PROFILE_KEYS, item_prefix, errors):
            continue
        principal_id = profile.get("principalId")
        if not isinstance(principal_id, str) or not principal_id or principal_id in result:
            errors.append(f"{prefix}-principal-id-invalid-or-duplicate")
            continue
        if profile.get("role") != role:
            errors.append(f"{item_prefix}-role-invalid")
        if profile.get("algorithm") != "ed25519":
            errors.append(f"{item_prefix}-algorithm-invalid")
        result[principal_id] = profile
    return result


def _independence(
    profiles: list[dict[str, Any]],
    fields: tuple[str, ...],
    prefix: str,
    errors: list[str],
) -> None:
    for field in fields:
        values = [profile.get(field) for profile in profiles]
        if any(not isinstance(value, str) or not value for value in values):
            errors.append(f"{prefix}-{field}-missing")
        elif len(values) != len(set(values)):
            errors.append(f"{prefix}-{field}-overlap")


def _cross_independence(
    left: dict[str, Any],
    right: dict[str, Any],
    fields: tuple[str, ...],
    prefix: str,
    errors: list[str],
) -> None:
    for field in fields:
        if left.get(field) == right.get(field):
            errors.append(f"{prefix}-{field}-overlap")


def _load_f1_report(root: Path, history: Any) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "authenticated-history.json"
        path.write_text(json.dumps(history, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        return evaluate_f1(root, path)


def verify_activation_package(
    package: Any,
    root: Path,
    evaluation_at: str | None,
) -> dict[str, Any]:
    errors: list[str] = []
    summary: dict[str, Any] = {
        "historyDigest": None,
        "f1ReportDigest": None,
        "ingressReceiptDigest": None,
        "ingressReadbackSetDigest": None,
        "activationDigest": None,
        "activatedAt": None,
        "validUntil": None,
        "ingressObserverCount": 0,
        "activationWitnessCount": 0,
        "activationReadbackCount": 0,
    }
    if not _shape(package, PACKAGE_KEYS, "activation-package", errors):
        return {"verified": False, "errors": sorted(set(errors)), "summary": summary}

    source = package.get("source")
    if _shape(source, SOURCE_KEYS, "source", errors):
        if source.get("f1Head") != F1_HEAD or source.get("f1Tree") != F1_TREE:
            errors.append("source-f1-binding-mismatch")
    if package.get("standard") != "EIGIIB-M0-A15-F2-ACTIVATION-PACKAGE-1.0":
        errors.append("activation-package-standard-invalid")
    if package.get("evidenceClass") != "external-authenticated-history":
        errors.append("evidence-class-invalid")

    history = package.get("history")
    try:
        derived_history_digest = digest_hex(history)
        history_bytes = len(canonical_bytes(history))
    except Exception:
        derived_history_digest = None
        history_bytes = -1
        errors.append("history-canonicalization-failed")
    summary["historyDigest"] = derived_history_digest
    if package.get("historyDigest") != derived_history_digest:
        errors.append("history-digest-mismatch")

    carrier = package.get("carrier")
    retrieved_at = None
    if _shape(carrier, CARRIER_KEYS, "carrier", errors):
        if carrier.get("mediaType") != MEDIA_TYPE:
            errors.append("carrier-media-type-invalid")
        if carrier.get("contentLength") != history_bytes:
            errors.append("carrier-content-length-mismatch")
        if not isinstance(carrier.get("carrierId"), str) or not carrier.get("carrierId"):
            errors.append("carrier-id-invalid")
        if not _valid_external_locator(carrier.get("locator")):
            errors.append("carrier-locator-not-external-https")
        retrieved_at = parse_time(carrier.get("retrievedAt"))
        if retrieved_at is None:
            errors.append("carrier-retrieved-at-invalid")

    publisher = package.get("publisher")
    if not _shape(publisher, PROFILE_KEYS, "publisher", errors):
        publisher = {}
    elif publisher.get("role") != "publisher":
        errors.append("publisher-role-invalid")

    observer_map = _profile_map(
        package.get("observers"), "observer", MIN_INGRESS_OBSERVERS, "observer", errors
    )
    observer_profiles = list(observer_map.values())
    _independence(
        observer_profiles,
        ("controlDomainId", "identityRoot", "providerOperator", "networkPath", "implementation"),
        "observer-independence",
        errors,
    )

    activation_authority = package.get("activationAuthority")
    if not _shape(activation_authority, PROFILE_KEYS, "activation-authority", errors):
        activation_authority = {}
    elif activation_authority.get("role") != "activation-authority":
        errors.append("activation-authority-role-invalid")

    witness_map = _profile_map(
        package.get("activationWitnesses"), "activation-witness", 4, "activation-witness", errors
    )
    witness_profiles = list(witness_map.values())
    _independence(
        witness_profiles,
        ("controlDomainId", "identityRoot", "providerOperator"),
        "activation-witness-independence",
        errors,
    )
    if publisher and activation_authority:
        _cross_independence(
            publisher,
            activation_authority,
            ("controlDomainId", "identityRoot", "providerOperator"),
            "publisher-activation-authority",
            errors,
        )
    for observer in observer_profiles:
        if publisher:
            _cross_independence(
                publisher,
                observer,
                ("controlDomainId", "identityRoot", "providerOperator"),
                "publisher-observer",
                errors,
            )
        if activation_authority:
            _cross_independence(
                activation_authority,
                observer,
                ("controlDomainId", "identityRoot", "providerOperator"),
                "activation-authority-observer",
                errors,
            )
    for witness in witness_profiles:
        if activation_authority:
            _cross_independence(
                activation_authority,
                witness,
                ("controlDomainId", "identityRoot", "providerOperator"),
                "activation-authority-witness",
                errors,
            )

    ingress_receipt = package.get("ingressReceipt")
    ingress_receipt_digest, ingress_signature_errors = verify_envelope(
        ingress_receipt, publisher, "ingress-receipt"
    )
    errors.extend(ingress_signature_errors)
    summary["ingressReceiptDigest"] = ingress_receipt_digest
    ingress_payload = ingress_receipt.get("payload") if isinstance(ingress_receipt, dict) else None
    expected_ingress_payload = {
        "recordType": "external-history-ingress",
        "sourceF1Head": F1_HEAD,
        "sourceF1Tree": F1_TREE,
        "historyDigest": derived_history_digest,
        "historyBytes": history_bytes,
        "carrierId": carrier.get("carrierId") if isinstance(carrier, dict) else None,
        "carrierLocator": carrier.get("locator") if isinstance(carrier, dict) else None,
        "retrievedAt": carrier.get("retrievedAt") if isinstance(carrier, dict) else None,
        "publisherId": publisher.get("principalId") if isinstance(publisher, dict) else None,
    }
    if not _shape(ingress_payload, INGRESS_PAYLOAD_KEYS, "ingress-receipt-payload", errors):
        pass
    elif ingress_payload != expected_ingress_payload:
        errors.append("ingress-receipt-not-derived")

    activation = package.get("activation")
    if not _shape(activation, ACTIVATION_KEYS, "activation", errors):
        activation = {}
    activation_envelope = activation.get("envelope") if isinstance(activation, dict) else None
    activation_payload = activation_envelope.get("payload") if isinstance(activation_envelope, dict) else None
    activated_at = parse_time(activation_payload.get("activatedAt")) if isinstance(activation_payload, dict) else None
    valid_until = parse_time(activation_payload.get("validUntil")) if isinstance(activation_payload, dict) else None
    summary["activatedAt"] = activation_payload.get("activatedAt") if isinstance(activation_payload, dict) else None
    summary["validUntil"] = activation_payload.get("validUntil") if isinstance(activation_payload, dict) else None

    valid_ingress_observers: set[str] = set()
    ingress_readback_digests: list[str] = []
    ingress_readbacks = package.get("ingressReadbacks")
    if not isinstance(ingress_readbacks, list):
        errors.append("ingress-readbacks-invalid")
        ingress_readbacks = []
    for index, envelope in enumerate(ingress_readbacks, 1):
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        observer_id = payload.get("observerId") if isinstance(payload, dict) else None
        profile = observer_map.get(observer_id)
        envelope_digest, envelope_errors = verify_envelope(envelope, profile, f"ingress-readback-{index}")
        errors.extend(envelope_errors)
        if envelope_digest:
            ingress_readback_digests.append(digest_hex(envelope))
        if not _shape(payload, INGRESS_READBACK_KEYS, f"ingress-readback-{index}-payload", errors):
            continue
        expected = {
            "recordType": "external-history-readback",
            "observerId": observer_id,
            "controlDomainId": profile.get("controlDomainId") if profile else None,
            "historyDigest": derived_history_digest,
            "ingressReceiptDigest": ingress_receipt_digest,
            "carrierId": carrier.get("carrierId") if isinstance(carrier, dict) else None,
            "carrierLocator": carrier.get("locator") if isinstance(carrier, dict) else None,
            "observedAt": payload.get("observedAt"),
        }
        if payload != expected:
            errors.append(f"ingress-readback-{index}-binding-mismatch")
            continue
        observed_at = parse_time(payload.get("observedAt"))
        if observed_at is None or retrieved_at is None or observed_at < retrieved_at:
            errors.append(f"ingress-readback-{index}-time-invalid")
        elif activated_at is not None and observed_at > activated_at:
            errors.append(f"ingress-readback-{index}-after-activation")
        else:
            valid_ingress_observers.add(observer_id)
    if len(valid_ingress_observers) < MIN_INGRESS_OBSERVERS:
        errors.append("independent-ingress-readback-quorum-not-met")
    summary["ingressObserverCount"] = len(valid_ingress_observers)
    ingress_readback_set_digest = digest_hex(sorted(ingress_readback_digests))
    summary["ingressReadbackSetDigest"] = ingress_readback_set_digest

    f1_report = _load_f1_report(root, history)
    f1_report_digest = digest_hex(f1_report)
    summary["f1ReportDigest"] = f1_report_digest
    if f1_report.get("htntLabel") != "T":
        errors.append("f1-exact-replay-not-t")
        errors.extend(f"f1:{finding}" for finding in f1_report.get("findings", []))

    activation_digest, activation_signature_errors = verify_envelope(
        activation_envelope, activation_authority, "activation"
    )
    errors.extend(activation_signature_errors)
    summary["activationDigest"] = activation_digest
    expected_activation_payload = {
        "recordType": "point-in-time-activation",
        "sourceF1Head": F1_HEAD,
        "sourceF1Tree": F1_TREE,
        "historyDigest": derived_history_digest,
        "f1ReportDigest": f1_report_digest,
        "ingressReceiptDigest": ingress_receipt_digest,
        "ingressReadbackSetDigest": ingress_readback_set_digest,
        "activationSequence": 1,
        "previousActivationDigest": None,
        "activationNonce": activation_payload.get("activationNonce") if isinstance(activation_payload, dict) else None,
        "activatedAt": activation_payload.get("activatedAt") if isinstance(activation_payload, dict) else None,
        "validUntil": activation_payload.get("validUntil") if isinstance(activation_payload, dict) else None,
        "decision": "m0-a15-f2-t-closure",
    }
    if not _shape(activation_payload, ACTIVATION_PAYLOAD_KEYS, "activation-payload", errors):
        pass
    elif activation_payload != expected_activation_payload:
        errors.append("activation-payload-not-derived")
    if not is_hex(expected_activation_payload.get("activationNonce")):
        errors.append("activation-nonce-invalid")

    evaluation_time = parse_time(evaluation_at)
    if evaluation_time is None:
        errors.append("evaluation-time-required-and-invalid")
    if retrieved_at is None or activated_at is None or valid_until is None:
        errors.append("activation-time-chain-invalid")
    else:
        if not (retrieved_at <= activated_at < valid_until):
            errors.append("activation-time-order-invalid")
        if (activated_at - retrieved_at).total_seconds() > MAX_INGRESS_TO_ACTIVATION_SECONDS:
            errors.append("ingress-to-activation-window-exceeded")
        if (valid_until - activated_at).total_seconds() > MAX_ACTIVATION_WINDOW_SECONDS:
            errors.append("activation-validity-window-exceeded")
        if evaluation_time is not None and not (activated_at <= evaluation_time <= valid_until):
            errors.append("evaluation-time-outside-activation-window")

    valid_witnesses: set[str] = set()
    endorsements = activation.get("witnessEndorsements") if isinstance(activation, dict) else None
    if not isinstance(endorsements, list):
        errors.append("activation-witness-endorsements-invalid")
        endorsements = []
    for index, envelope in enumerate(endorsements, 1):
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        witness_id = payload.get("witnessId") if isinstance(payload, dict) else None
        profile = witness_map.get(witness_id)
        _, envelope_errors = verify_envelope(envelope, profile, f"activation-endorsement-{index}")
        errors.extend(envelope_errors)
        if not _shape(payload, ACTIVATION_ENDORSEMENT_KEYS, f"activation-endorsement-{index}-payload", errors):
            continue
        expected = {
            "recordType": "point-in-time-activation-endorsement",
            "witnessId": witness_id,
            "controlDomainId": profile.get("controlDomainId") if profile else None,
            "activationDigest": activation_digest,
            "signedAt": payload.get("signedAt"),
        }
        if payload != expected:
            errors.append(f"activation-endorsement-{index}-binding-mismatch")
            continue
        signed_at = parse_time(payload.get("signedAt"))
        if signed_at is None or activated_at is None or valid_until is None or not (activated_at <= signed_at <= valid_until):
            errors.append(f"activation-endorsement-{index}-time-invalid")
        else:
            valid_witnesses.add(witness_id)
    if len(valid_witnesses) < MIN_ACTIVATION_WITNESSES:
        errors.append("activation-witness-quorum-not-met")
    summary["activationWitnessCount"] = len(valid_witnesses)

    valid_activation_observers: set[str] = set()
    activation_readbacks = activation.get("readbacks") if isinstance(activation, dict) else None
    if not isinstance(activation_readbacks, list):
        errors.append("activation-readbacks-invalid")
        activation_readbacks = []
    for index, envelope in enumerate(activation_readbacks, 1):
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        observer_id = payload.get("observerId") if isinstance(payload, dict) else None
        profile = observer_map.get(observer_id)
        _, envelope_errors = verify_envelope(envelope, profile, f"activation-readback-{index}")
        errors.extend(envelope_errors)
        if not _shape(payload, ACTIVATION_READBACK_KEYS, f"activation-readback-{index}-payload", errors):
            continue
        expected = {
            "recordType": "point-in-time-activation-readback",
            "observerId": observer_id,
            "controlDomainId": profile.get("controlDomainId") if profile else None,
            "activationDigest": activation_digest,
            "historyDigest": derived_history_digest,
            "f1ReportDigest": f1_report_digest,
            "scope": "published-point-in-time-activation",
            "observedAt": payload.get("observedAt"),
        }
        if payload != expected:
            errors.append(f"activation-readback-{index}-binding-mismatch")
            continue
        observed_at = parse_time(payload.get("observedAt"))
        if observed_at is None or activated_at is None or valid_until is None or not (activated_at <= observed_at <= valid_until):
            errors.append(f"activation-readback-{index}-time-invalid")
        else:
            valid_activation_observers.add(observer_id)
    if len(valid_activation_observers) < MIN_ACTIVATION_READBACKS:
        errors.append("independent-activation-readback-quorum-not-met")
    summary["activationReadbackCount"] = len(valid_activation_observers)

    return {
        "verified": not errors,
        "errors": sorted(set(errors)),
        "summary": summary,
        "f1Report": f1_report,
    }
