"""Corpus validation and deterministic mutation generation for P1-A7.4."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from eigiib_signature_replay_common import (
    MEMBER_ORDER,
    PLATFORMS,
    PROFILE,
    ROUTES,
    STANDARD,
    TOOL_VERSION,
    check_identity,
    confined_regular_file,
    load_json,
    taxonomy_ranks,
)


def source_seed(
    root: Path,
    corpus: dict[str, Any],
    adapter: Any,
    openssl: str,
) -> bytes:
    bundle_ref = corpus.get("sourceBundle")
    key_ref = corpus.get("sourcePublicKey")
    if not isinstance(bundle_ref, dict) or set(bundle_ref) != {"path", "identity"}:
        raise ValueError("sourceBundle fields differ from contract")
    if not isinstance(key_ref, dict) or set(key_ref) != {"path", "identity"}:
        raise ValueError("sourcePublicKey fields differ from contract")
    bundle_path = confined_regular_file(root, bundle_ref["path"])
    key_path = confined_regular_file(root, key_ref["path"])
    bundle_raw = bundle_path.read_bytes()
    key_raw = key_path.read_bytes()
    check_identity(adapter, bundle_raw, bundle_ref["identity"], "source bundle")
    check_identity(adapter, key_raw, key_ref["identity"], "source public key")

    bundle = load_json(adapter, bundle_path, "P1A7.4.SOURCE.BUNDLE")
    if not isinstance(bundle, dict):
        raise ValueError("P1-A2 source bundle root must be object")
    if bundle.get("standard") != "EIGIIB-P1-A2-1.0":
        raise ValueError("P1-A2 source standard mismatch")
    container = bundle.get("bundle")
    if not isinstance(container, dict):
        raise ValueError("P1-A2 bundle carrier missing")
    envelope = container.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise ValueError("P1-A2 DSSE envelope missing")

    key_text = key_raw.decode("utf-8", errors="strict")
    _, der = adapter.parse_public_key_pem(key_text)
    payload = adapter.decode_canonical_b64(envelope.get("payload"))
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError("P1-A2 source must carry exactly one signature")
    signature = adapter.decode_canonical_b64(signatures[0].get("sig"))
    carrier = {
        "standard": adapter.CARRIER_STANDARD,
        "profile": adapter.PROFILE,
        "manifest": {
            "members": [
                {"name": "payload", "identity": adapter.identity(payload)},
                {"name": "signature", "identity": adapter.identity(signature)},
                {"name": "public-key-spki", "identity": adapter.identity(der)},
            ]
        },
        "dsseEnvelope": copy.deepcopy(envelope),
        "publicKeyPem": key_text,
    }
    raw = adapter.canonical_json(carrier)
    positive = adapter.evaluate(raw, "a7-positive-p1-a2-carrier", openssl)
    if not positive.accepted:
        raise ValueError(
            f"P1-A2 source does not produce a valid A7.4 carrier: "
            f"{positive.error_class}@{positive.boundary}"
        )
    return raw


def _member(document: dict[str, Any], name: str) -> dict[str, Any]:
    manifest = document.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("manifest missing")
    members = manifest.get("members")
    if not isinstance(members, list):
        raise ValueError("manifest members missing")
    for row in members:
        if isinstance(row, dict) and row.get("name") == name:
            return row
    raise ValueError(f"manifest member missing: {name}")


def _current_member_bytes(adapter: Any, document: dict[str, Any], name: str) -> bytes:
    envelope = document.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise ValueError("DSSE envelope missing")
    if name == "payload":
        return adapter.decode_canonical_b64(envelope.get("payload"))
    if name == "signature":
        signatures = envelope.get("signatures")
        if not isinstance(signatures, list) or len(signatures) != 1:
            raise ValueError("signature carrier is not singular")
        return adapter.decode_canonical_b64(signatures[0].get("sig"))
    if name == "public-key-spki":
        _, der = adapter.parse_public_key_pem(document.get("publicKeyPem"))
        return der
    raise ValueError(f"unknown member name: {name}")


def apply_mutations(adapter: Any, seed: bytes, mutations: Any) -> bytes:
    if not isinstance(mutations, list) or not mutations:
        raise ValueError("mutations must be non-empty array")
    document = adapter.strict_json_loads(seed, "P1A7.4.SEED")
    if not isinstance(document, dict):
        raise ValueError("seed root must be object")
    for mutation in mutations:
        if not isinstance(mutation, dict):
            raise ValueError("mutation must be object")
        operator = mutation.get("operator")
        envelope = document.get("dsseEnvelope")
        if not isinstance(envelope, dict):
            raise ValueError("DSSE envelope missing")

        if operator == "manifest.delete-member":
            name = mutation.get("name")
            members = document["manifest"]["members"]
            before = len(members)
            document["manifest"]["members"] = [
                row for row in members
                if not isinstance(row, dict) or row.get("name") != name
            ]
            if len(document["manifest"]["members"]) == before:
                raise ValueError("manifest.delete-member target missing")
        elif operator == "manifest.swap-members":
            first = mutation.get("first")
            second = mutation.get("second")
            members = document["manifest"]["members"]
            positions = {
                row.get("name"): index
                for index, row in enumerate(members)
                if isinstance(row, dict)
            }
            if first not in positions or second not in positions:
                raise ValueError("manifest.swap-members target missing")
            a, b = positions[first], positions[second]
            members[a], members[b] = members[b], members[a]
        elif operator == "manifest.set-digest":
            value = mutation.get("value")
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError("manifest.set-digest requires 64-character value")
            _member(document, mutation.get("name"))["identity"]["digest"] = value
        elif operator == "manifest.refresh-member":
            name = mutation.get("name")
            _member(document, name)["identity"] = adapter.identity(
                _current_member_bytes(adapter, document, name)
            )
        elif operator == "dsse.set-payload-type":
            value = mutation.get("value")
            if not isinstance(value, str) or not value:
                raise ValueError("dsse.set-payload-type requires non-empty string")
            envelope["payloadType"] = value
        elif operator == "dsse.append-payload-hex":
            encoded = mutation.get("hex")
            if not isinstance(encoded, str) or not encoded or len(encoded) % 2:
                raise ValueError("dsse.append-payload-hex requires complete bytes")
            payload = adapter.decode_canonical_b64(envelope.get("payload"))
            envelope["payload"] = adapter.canonical_b64(payload + bytes.fromhex(encoded))
        elif operator == "dsse.truncate-signature":
            count = mutation.get("bytes")
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                raise ValueError("dsse.truncate-signature bytes must be positive")
            signature = adapter.decode_canonical_b64(envelope["signatures"][0].get("sig"))
            if count >= len(signature):
                raise ValueError("signature truncation removes complete signature")
            envelope["signatures"][0]["sig"] = adapter.canonical_b64(signature[:-count])
        elif operator == "dsse.flip-signature-byte":
            index = mutation.get("index")
            mask = mutation.get("mask")
            signature = bytearray(
                adapter.decode_canonical_b64(envelope["signatures"][0].get("sig"))
            )
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index >= len(signature)
                or not isinstance(mask, int)
                or isinstance(mask, bool)
                or mask < 1
                or mask > 255
            ):
                raise ValueError("invalid signature bit-flip parameters")
            signature[index] ^= mask
            envelope["signatures"][0]["sig"] = adapter.canonical_b64(bytes(signature))
        elif operator == "dsse.set-keyid":
            value = mutation.get("value")
            if not isinstance(value, str) or not value:
                raise ValueError("dsse.set-keyid requires non-empty string")
            envelope["signatures"][0]["keyid"] = value
        else:
            raise ValueError(f"unknown mutation operator: {operator!r}")
    return adapter.canonical_json(document)


def validate_corpus(
    root: Path,
    corpus_path: Path,
    adapter: Any,
    openssl: str,
) -> tuple[bytes, list[dict[str, Any]], dict[str, int]]:
    corpus = load_json(adapter, corpus_path, "P1A7.4.CORPUS")
    if not isinstance(corpus, dict):
        raise ValueError("corpus root must be object")
    expected_fields = {
        "standard",
        "profile",
        "generator",
        "taxonomy",
        "sourceBundle",
        "sourcePublicKey",
        "requiredRoutes",
        "requiredPlatforms",
        "vectors",
        "claimBoundary",
    }
    if set(corpus) != expected_fields:
        raise ValueError("corpus fields differ from contract")
    if corpus.get("standard") != STANDARD or corpus.get("profile") != PROFILE:
        raise ValueError("corpus constants differ from contract")
    if corpus.get("requiredRoutes") != ROUTES or corpus.get("requiredPlatforms") != PLATFORMS:
        raise ValueError("required routes or platforms differ from contract")
    if corpus.get("generator") != {
        "tool": "tools/eigiib_signature_route_replay.py",
        "version": TOOL_VERSION,
        "canonicalJson": "utf8-sort-keys-indent-2-lf-v1",
        "sequenceMode": "ordered-application-v1",
    }:
        raise ValueError("generator declaration differs from contract")

    taxonomy_ref = corpus.get("taxonomy")
    if not isinstance(taxonomy_ref, dict) or set(taxonomy_ref) != {"path", "identity"}:
        raise ValueError("taxonomy reference differs from contract")
    taxonomy_path = confined_regular_file(root, taxonomy_ref["path"])
    taxonomy_raw = taxonomy_path.read_bytes()
    check_identity(adapter, taxonomy_raw, taxonomy_ref["identity"], "taxonomy")
    ranks = taxonomy_ranks(load_json(adapter, taxonomy_path, "P1A7.4.TAXONOMY"))
    for class_id in ("manifest.invalid", "signature.malformed", "signature.invalid"):
        if class_id not in ranks:
            raise ValueError(f"taxonomy lacks required class: {class_id}")

    seed = source_seed(root, corpus, adapter, openssl)
    vectors = corpus.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("vectors must be non-empty array")
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for vector in vectors:
        if not isinstance(vector, dict) or set(vector) != {
            "id",
            "layer",
            "mutations",
            "expect",
            "requiredRoutes",
            "requiredPlatforms",
            "claimBoundary",
        }:
            raise ValueError("vector fields differ from contract")
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or not vector_id or vector_id in seen:
            raise ValueError("vector IDs must be unique non-empty strings")
        seen.add(vector_id)
        if vector.get("requiredRoutes") != ROUTES or vector.get("requiredPlatforms") != PLATFORMS:
            raise ValueError(f"{vector_id}: route or platform set differs")
        expect = vector.get("expect")
        if not isinstance(expect, dict) or set(expect) != {
            "accepted",
            "errorClass",
            "boundary",
            "precedence",
        }:
            raise ValueError(f"{vector_id}: expectation fields differ")
        if expect.get("accepted") is not False:
            raise ValueError(f"{vector_id}: negative vector must reject")
        error_class = expect.get("errorClass")
        precedence = expect.get("precedence")
        if error_class not in ranks:
            raise ValueError(f"{vector_id}: unknown error class")
        if (
            not isinstance(precedence, list)
            or not precedence
            or len(precedence) != len(set(precedence))
            or any(item not in ranks for item in precedence)
        ):
            raise ValueError(f"{vector_id}: invalid precedence list")
        if precedence != sorted(precedence, key=ranks.__getitem__) or precedence[0] != error_class:
            raise ValueError(f"{vector_id}: precedence differs from taxonomy")
        first = apply_mutations(adapter, seed, vector.get("mutations"))
        second = apply_mutations(adapter, seed, vector.get("mutations"))
        if first != second:
            raise ValueError(f"{vector_id}: mutation generation is non-deterministic")
        rows.append(
            {
                "id": vector_id,
                "bytes": first,
                "expected_class": error_class,
                "expected_boundary": expect.get("boundary"),
                "precedence": precedence,
            }
        )
    return seed, rows, ranks
