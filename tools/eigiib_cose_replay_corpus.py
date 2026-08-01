"""Corpus validation and deterministic mutation generation for P1-A7.5."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from eigiib_cose_replay_common import (
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
) -> tuple[bytes, str, Path]:
    capsule_ref = corpus.get("sourceCapsule")
    key_ref = corpus.get("sourceIssuerKey")
    if not isinstance(capsule_ref, dict) or set(capsule_ref) != {
        "path",
        "standard",
        "profile",
        "signedStatementIdentity",
    }:
        raise ValueError("sourceCapsule fields differ from contract")
    if not isinstance(key_ref, dict) or set(key_ref) != {"path", "rawIdentity", "derIdentity"}:
        raise ValueError("sourceIssuerKey fields differ from contract")

    capsule_path = confined_regular_file(root, capsule_ref["path"])
    key_path = confined_regular_file(root, key_ref["path"])
    capsule = load_json(adapter, capsule_path, "P1A7.5.SOURCE.CAPSULE")
    if not isinstance(capsule, dict):
        raise ValueError("source capsule root must be object")
    if capsule.get("standard") != capsule_ref["standard"] or capsule.get("profile") != capsule_ref["profile"]:
        raise ValueError("source capsule constants differ")
    signed = capsule.get("signedStatement")
    if not isinstance(signed, dict) or set(signed) != {
        "data",
        "encoding",
        "identity",
        "issuerKeySpki",
    }:
        raise ValueError("source Signed Statement fields differ")
    if signed.get("encoding") != "base64-cbor":
        raise ValueError("source Signed Statement encoding differs")
    raw = adapter.decode_canonical_b64(signed.get("data"))
    if signed.get("identity") != capsule_ref["signedStatementIdentity"]:
        raise ValueError("source Signed Statement declared identity differs")
    check_identity(adapter, raw, capsule_ref["signedStatementIdentity"], "source Signed Statement")

    key_raw = key_path.read_bytes()
    check_identity(adapter, key_raw, key_ref["rawIdentity"], "source issuer key")
    key_text = key_raw.decode("utf-8", errors="strict")
    _, der = adapter.parse_public_key_pem(key_text)
    check_identity(adapter, der, key_ref["derIdentity"], "source issuer key DER")
    if signed.get("issuerKeySpki") != key_ref["derIdentity"]:
        raise ValueError("source Signed Statement key binding differs")

    positive = adapter.evaluate(raw, key_text, "a7-positive-p1-a3-signed-statement", openssl)
    if not positive.accepted:
        raise ValueError(
            f"source Signed Statement does not satisfy A7.5 positive profile: "
            f"{positive.error_class}@{positive.boundary}"
        )
    return raw, key_text, key_path


def _parts(adapter: Any, raw: bytes) -> tuple[Any, list[Any], bytes, Any, bytes, bytes]:
    value = adapter.decode_cbor(raw)
    if not isinstance(value, adapter.CborTag) or not isinstance(value.value, list) or len(value.value) != 4:
        raise ValueError("seed is not tagged COSE_Sign1")
    protected_raw, unprotected, payload, signature = value.value
    if not isinstance(protected_raw, bytes) or not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise ValueError("seed COSE_Sign1 types differ")
    return value, list(value.value), protected_raw, unprotected, payload, signature


def _replace_map(adapter: Any, mapping: Any, key: Any, value: Any) -> Any:
    if not isinstance(mapping, adapter.CborMap):
        raise ValueError("protected header is not a map")
    return adapter.map_replace(mapping, key, value)


def apply_mutations(adapter: Any, seed: bytes, mutations: Any) -> bytes:
    if not isinstance(mutations, list) or not mutations:
        raise ValueError("mutations must be a non-empty array")
    raw = seed
    for mutation in mutations:
        if not isinstance(mutation, dict):
            raise ValueError("mutation must be object")
        operator = mutation.get("operator")
        value, members, protected_raw, unprotected, payload, signature = _parts(adapter, raw)

        if operator == "cbor.nonminimal-tag":
            if raw[:1] != bytes([0xD2]):
                raise ValueError("source tag is not canonical tag 18")
            raw = bytes([0xD9, 0x00, 0x12]) + raw[1:]
            continue
        if operator == "cbor.reverse-protected-map":
            protected = adapter.decode_cbor(protected_raw)
            if not isinstance(protected, adapter.CborMap) or len(protected.pairs) < 2:
                raise ValueError("protected header cannot be reversed")
            members[0] = adapter.encode_cbor(
                adapter.CborMap(tuple(reversed(protected.pairs))),
                canonical_maps=False,
            )
            raw = adapter.encode_cbor(adapter.CborTag(value.number, members))
            continue
        if operator == "cbor.reverse-payload-map":
            payload_value = adapter.decode_cbor(payload)
            if not isinstance(payload_value, adapter.CborMap) or len(payload_value.pairs) < 2:
                raise ValueError("payload map cannot be reversed")
            members[2] = adapter.encode_cbor(
                adapter.CborMap(tuple(reversed(payload_value.pairs))),
                canonical_maps=False,
            )
            raw = adapter.encode_cbor(adapter.CborTag(value.number, members))
            continue
        if operator == "cose.set-tag":
            tag = mutation.get("value")
            if not isinstance(tag, int) or isinstance(tag, bool) or tag < 0:
                raise ValueError("cose.set-tag requires non-negative integer")
            raw = adapter.encode_cbor(adapter.CborTag(tag, members))
            continue
        if operator == "cose.protected-as-map":
            members[0] = adapter.decode_cbor(protected_raw)
            raw = adapter.encode_cbor(adapter.CborTag(value.number, members))
            continue

        protected = adapter.decode_cbor(protected_raw)
        if operator == "cose.set-algorithm":
            algorithm = mutation.get("value")
            if not isinstance(algorithm, int) or isinstance(algorithm, bool):
                raise ValueError("cose.set-algorithm requires integer")
            protected = _replace_map(adapter, protected, 1, algorithm)
        elif operator == "cose.add-unknown-critical":
            label = mutation.get("label")
            if not isinstance(label, int) or isinstance(label, bool) or label < 17:
                raise ValueError("unknown critical label must be integer >= 17")
            protected = _replace_map(adapter, protected, 2, [label])
            protected = _replace_map(adapter, protected, label, True)
        elif operator == "cose.set-malformed-critical":
            protected = _replace_map(adapter, protected, 2, mutation.get("value"))
        else:
            raise ValueError(f"unknown mutation operator: {operator!r}")
        members[0] = adapter.encode_cbor(protected)
        raw = adapter.encode_cbor(adapter.CborTag(value.number, members))
    return raw


def validate_corpus(
    root: Path,
    corpus_path: Path,
    adapter: Any,
    openssl: str,
) -> tuple[bytes, str, Path, list[dict[str, Any]], dict[str, int]]:
    corpus = load_json(adapter, corpus_path, "P1A7.5.CORPUS")
    if not isinstance(corpus, dict):
        raise ValueError("corpus root must be object")
    expected_fields = {
        "standard",
        "profile",
        "generator",
        "taxonomy",
        "sourceCapsule",
        "sourceIssuerKey",
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
        "tool": "tools/eigiib_cose_route_replay.py",
        "version": TOOL_VERSION,
        "encoding": "deterministic-cbor-rfc8949-profile-v1",
        "sequenceMode": "ordered-application-v1",
    }:
        raise ValueError("generator declaration differs from contract")

    taxonomy_ref = corpus.get("taxonomy")
    if not isinstance(taxonomy_ref, dict) or set(taxonomy_ref) != {"path", "identity"}:
        raise ValueError("taxonomy reference differs from contract")
    taxonomy_path = confined_regular_file(root, taxonomy_ref["path"])
    taxonomy_raw = taxonomy_path.read_bytes()
    check_identity(adapter, taxonomy_raw, taxonomy_ref["identity"], "taxonomy")
    ranks = taxonomy_ranks(load_json(adapter, taxonomy_path, "P1A7.5.TAXONOMY"))
    for class_id in ("cbor.nondeterministic", "cose.unsupported-header", "cose.invalid-structure"):
        if class_id not in ranks:
            raise ValueError(f"taxonomy lacks required class: {class_id}")

    seed, key_text, key_path = source_seed(root, corpus, adapter, openssl)
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
    return seed, key_text, key_path, rows, ranks
