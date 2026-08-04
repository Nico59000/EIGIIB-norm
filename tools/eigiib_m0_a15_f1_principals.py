#!/usr/bin/env python3
"""Principal inventories, signature quorum and readback admission for M0-A15-F1."""
from __future__ import annotations

from typing import Any

from eigiib_m0_a15_f1_canonical import parse_time
from eigiib_m0_a15_f1_crypto import verify_envelope
from eigiib_m0_a15_f1_model import (
    ENDORSEMENT_KEYS, OBSERVER_DIMENSIONS, OBSERVER_PROFILE_KEYS, READBACK_KEYS,
    REGISTRY_DIMENSIONS, REGISTRY_IDS, REGISTRY_PROFILE_KEYS, WITNESS_PROFILE_KEYS,
    WITNESS_QUORUM, shape,
)


def profile_maps(case: dict[str, Any], errors: list[str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    registries = case.get("registries", [])
    witnesses = case.get("witnesses", [])
    observers = case.get("readbackObservers", [])
    if not isinstance(registries, list) or len(registries) != 3:
        errors.append("registry-inventory-invalid"); registries = []
    if not isinstance(witnesses, list) or len(witnesses) != 5:
        errors.append("witness-inventory-invalid"); witnesses = []
    if not isinstance(observers, list) or len(observers) < 2:
        errors.append("readback-observer-inventory-invalid"); observers = []

    for profile in registries: shape(profile, REGISTRY_PROFILE_KEYS, "registry-profile", errors)
    for profile in witnesses: shape(profile, WITNESS_PROFILE_KEYS, "witness-profile", errors)
    for profile in observers: shape(profile, OBSERVER_PROFILE_KEYS, "observer-profile", errors)

    registry_map = {p.get("registryId"): p for p in registries if isinstance(p, dict)}
    witness_map = {p.get("witnessId"): p for p in witnesses if isinstance(p, dict)}
    observer_map = {p.get("observerId"): p for p in observers if isinstance(p, dict)}
    if set(registry_map) != set(REGISTRY_IDS) or len(registry_map) != 3: errors.append("registry-inventory-invalid")
    if len(witness_map) != 5 or None in witness_map: errors.append("witness-inventory-invalid")
    if len(observer_map) != len(observers) or None in observer_map: errors.append("readback-observer-inventory-invalid")

    for dimension in REGISTRY_DIMENSIONS:
        values = [profile.get(dimension) for profile in registries]
        if any(not isinstance(value, str) or not value for value in values) or len(set(values)) != 3:
            errors.append(f"registry-independence-{dimension}-invalid")
    witness_domains = [p.get("controlDomainId") for p in witnesses]
    witness_roots = [p.get("identityRoot") for p in witnesses]
    if len(set(witness_domains)) != 5 or any(not value for value in witness_domains): errors.append("witness-control-domains-not-independent")
    if len(set(witness_roots)) != 5 or any(not value for value in witness_roots): errors.append("witness-identity-roots-not-independent")
    registry_roots = {p.get("identityRoot") for p in registries}
    if registry_roots & set(witness_roots): errors.append("witness-registry-identity-overlap")

    for dimension in OBSERVER_DIMENSIONS:
        values = [profile.get(dimension) for profile in observers]
        if any(not isinstance(value, str) or not value for value in values) or len(set(values)) != len(values):
            errors.append(f"observer-independence-{dimension}-invalid")
    observer_roots = {p.get("identityRoot") for p in observers}
    observer_domains = {p.get("controlDomainId") for p in observers}
    if observer_roots & (registry_roots | set(witness_roots)): errors.append("observer-identity-overlap")
    if observer_domains & set(witness_domains): errors.append("observer-witness-control-domain-overlap")

    principals = registries + witnesses + observers
    key_ids = [p.get("keyId") for p in principals]
    public_keys = [p.get("publicKey") for p in principals]
    if any(not value for value in key_ids) or len(set(key_ids)) != len(key_ids): errors.append("principal-key-id-inventory-invalid")
    if any(not value for value in public_keys) or len(set(public_keys)) != len(public_keys): errors.append("principal-public-key-inventory-invalid")
    if any(p.get("algorithm") != "ed25519" for p in principals): errors.append("principal-algorithm-invalid")
    return registry_map, witness_map, observer_map


def verify_witness_quorum(
    endorsements: Any, witness_map: dict[str, Any], record_type: str,
    record_digest: str, prefix: str, errors: list[str], not_before: Any = None,
) -> None:
    if not isinstance(endorsements, list):
        errors.append(f"{prefix}-witness-endorsements-invalid"); return
    valid_ids: set[str] = set(); valid_domains: set[str] = set()
    lower_bound = parse_time(not_before) if not_before is not None else None
    for index, envelope in enumerate(endorsements):
        item_prefix = f"{prefix}-witness-{index + 1}"
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        if not shape(payload, ENDORSEMENT_KEYS, item_prefix, errors): continue
        witness_id = payload.get("witnessId"); profile = witness_map.get(witness_id)
        if profile is None:
            errors.append(f"{item_prefix}-unknown-witness"); continue
        _, envelope_errors = verify_envelope(envelope, profile, item_prefix); errors.extend(envelope_errors)
        if payload.get("controlDomainId") != profile.get("controlDomainId"): errors.append(f"{item_prefix}-control-domain-binding-mismatch")
        if payload.get("recordType") != record_type or payload.get("recordDigest") != record_digest: errors.append(f"{item_prefix}-record-binding-mismatch")
        signed_at = parse_time(payload.get("signedAt"))
        if signed_at is None or (lower_bound is not None and signed_at < lower_bound): errors.append(f"{item_prefix}-time-invalid")
        if not envelope_errors:
            valid_ids.add(witness_id); valid_domains.add(profile.get("controlDomainId"))
    if len(valid_ids) < WITNESS_QUORUM: errors.append(f"{prefix}-witness-quorum-not-met")
    if len(valid_domains) < WITNESS_QUORUM: errors.append(f"{prefix}-witness-domains-not-independent")


def verify_readbacks(readbacks: Any, observer_map: dict[str, Any], prefix: str, errors: list[str]) -> list[dict[str, Any]]:
    if not isinstance(readbacks, list):
        errors.append(f"{prefix}-readbacks-invalid"); return []
    valid: list[dict[str, Any]] = []
    for index, envelope in enumerate(readbacks):
        item_prefix = f"{prefix}-readback-{index + 1}"
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        if not shape(payload, READBACK_KEYS, item_prefix, errors): continue
        profile = observer_map.get(payload.get("observerId"))
        if profile is None:
            errors.append(f"{item_prefix}-unknown-observer"); continue
        _, envelope_errors = verify_envelope(envelope, profile, item_prefix); errors.extend(envelope_errors)
        if payload.get("controlDomainId") != profile.get("controlDomainId"): errors.append(f"{item_prefix}-control-domain-binding-mismatch")
        if parse_time(payload.get("observedAt")) is None: errors.append(f"{item_prefix}-time-invalid")
        if not isinstance(payload.get("locator"), str) or not payload.get("locator"): errors.append(f"{item_prefix}-locator-invalid")
        if not envelope_errors: valid.append(payload)
    return valid
