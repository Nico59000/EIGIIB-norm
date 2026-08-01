"""Corpus validation for P1-A7.6."""
from __future__ import annotations
import copy
from pathlib import Path
from typing import Any
from eigiib_receipt_replay_common import (PLATFORMS, PROFILE, ROUTES, STANDARD, TOOL_VERSION, check_identity, confined_regular_file, load_json, taxonomy_ranks)
from eigiib_receipt_replay_mutations import apply_mutations

def source_seed(root: Path, corpus: dict[str, Any], adapter: Any, openssl: str) -> bytes:
    capsule_ref = corpus.get("sourceCapsule")
    key_ref = corpus.get("sourceTransparencyKey")
    if not isinstance(capsule_ref, dict) or set(capsule_ref) != {
        "path", "standard", "profile", "signedStatementIdentity", "receiptIdentity"
    }:
        raise ValueError("sourceCapsule fields differ from contract")
    if not isinstance(key_ref, dict) or set(key_ref) != {"path", "rawIdentity", "derIdentity"}:
        raise ValueError("sourceTransparencyKey fields differ from contract")
    capsule_path = confined_regular_file(root, capsule_ref["path"])
    key_path = confined_regular_file(root, key_ref["path"])
    capsule = load_json(adapter, capsule_path, "P1A7.6.SOURCE.CAPSULE")
    if not isinstance(capsule, dict) or capsule.get("standard") != capsule_ref["standard"] or capsule.get("profile") != capsule_ref["profile"]:
        raise ValueError("source capsule constants differ")
    binding = capsule.get("binding")
    signed = capsule.get("signedStatement")
    receipt = capsule.get("receipt")
    if not isinstance(binding, dict) or not isinstance(signed, dict) or not isinstance(receipt, dict):
        raise ValueError("source capsule carriers missing")
    signed_raw = adapter.decode_canonical_b64(signed.get("data"))
    receipt_raw = adapter.decode_canonical_b64(receipt.get("data"))
    check_identity(adapter, signed_raw, capsule_ref["signedStatementIdentity"], "source Signed Statement")
    check_identity(adapter, receipt_raw, capsule_ref["receiptIdentity"], "source Receipt")
    if signed.get("identity") != capsule_ref["signedStatementIdentity"] or receipt.get("identity") != capsule_ref["receiptIdentity"]:
        raise ValueError("source declared carrier identity differs")
    key_raw = key_path.read_bytes()
    check_identity(adapter, key_raw, key_ref["rawIdentity"], "source transparency key")
    key_text = key_raw.decode("utf-8", errors="strict")
    _, der = adapter.parse_public_key_pem(key_text)
    check_identity(adapter, der, key_ref["derIdentity"], "source transparency key DER")
    if receipt.get("transparencyServiceKeySpki") != key_ref["derIdentity"]:
        raise ValueError("source Receipt key binding differs")
    tree_size = binding.get("treeSize")
    leaf_index = binding.get("leafIndex")
    if tree_size != 1 or leaf_index != 0:
        raise ValueError("source coordinates differ from bounded fixture")
    carrier = {
        "standard": adapter.CARRIER_STANDARD,
        "profile": adapter.PROFILE,
        "binding": {
            "treeSize": tree_size,
            "leafIndex": leaf_index,
            "signedStatementIdentity": copy.deepcopy(capsule_ref["signedStatementIdentity"]),
        },
        "signedStatement": {"data": signed["data"], "identity": copy.deepcopy(signed["identity"])},
        "receipt": {"data": receipt["data"], "identity": copy.deepcopy(receipt["identity"])},
        "publicKeyPem": key_text,
    }
    raw = adapter.canonical_json(carrier)
    positive = adapter.evaluate(raw, "a7-positive-p1-a3-receipt", openssl)
    if not positive.accepted:
        raise ValueError(f"source Receipt does not satisfy A7.6 positive profile: {positive.error_class}@{positive.boundary}")
    return raw


def validate_corpus(root: Path, corpus_path: Path, adapter: Any, openssl: str) -> tuple[bytes, list[dict[str, Any]], dict[str, int]]:
    corpus = load_json(adapter, corpus_path, "P1A7.6.CORPUS")
    expected_fields = {"standard", "profile", "generator", "taxonomy", "sourceCapsule", "sourceTransparencyKey", "requiredRoutes", "requiredPlatforms", "vectors", "claimBoundary"}
    if not isinstance(corpus, dict) or set(corpus) != expected_fields:
        raise ValueError("corpus fields differ from contract")
    if corpus.get("standard") != STANDARD or corpus.get("profile") != PROFILE:
        raise ValueError("corpus constants differ")
    if corpus.get("requiredRoutes") != ROUTES or corpus.get("requiredPlatforms") != PLATFORMS:
        raise ValueError("required routes or platforms differ")
    if corpus.get("generator") != {"tool": "tools/eigiib_receipt_route_replay.py", "version": TOOL_VERSION, "encoding": "canonical-json-plus-deterministic-cbor-v1", "sequenceMode": "ordered-application-v1"}:
        raise ValueError("generator declaration differs")
    taxonomy_ref = corpus.get("taxonomy")
    if not isinstance(taxonomy_ref, dict) or set(taxonomy_ref) != {"path", "identity"}:
        raise ValueError("taxonomy reference differs")
    taxonomy_path = confined_regular_file(root, taxonomy_ref["path"])
    taxonomy_raw = taxonomy_path.read_bytes()
    check_identity(adapter, taxonomy_raw, taxonomy_ref["identity"], "taxonomy")
    ranks = taxonomy_ranks(load_json(adapter, taxonomy_path, "P1A7.6.TAXONOMY"))
    for class_id in ("cbor.nondeterministic", "cose.invalid-structure", "receipt.invalid-proof"):
        if class_id not in ranks:
            raise ValueError(f"taxonomy lacks required class: {class_id}")
    seed = source_seed(root, corpus, adapter, openssl)
    vectors = corpus.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("vectors must be non-empty array")
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for vector in vectors:
        if not isinstance(vector, dict) or set(vector) != {"id", "layer", "mutations", "expect", "requiredRoutes", "requiredPlatforms", "claimBoundary"}:
            raise ValueError("vector fields differ from contract")
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or not vector_id or vector_id in seen:
            raise ValueError("vector IDs must be unique non-empty strings")
        seen.add(vector_id)
        if vector.get("requiredRoutes") != ROUTES or vector.get("requiredPlatforms") != PLATFORMS:
            raise ValueError(f"{vector_id}: route or platform set differs")
        expect = vector.get("expect")
        if not isinstance(expect, dict) or set(expect) != {"accepted", "errorClass", "boundary", "precedence"} or expect.get("accepted") is not False:
            raise ValueError(f"{vector_id}: expectation differs")
        error_class = expect.get("errorClass")
        precedence = expect.get("precedence")
        if error_class not in ranks or not isinstance(precedence, list) or not precedence or len(precedence) != len(set(precedence)) or any(item not in ranks for item in precedence):
            raise ValueError(f"{vector_id}: invalid error class or precedence")
        if precedence != sorted(precedence, key=ranks.__getitem__) or precedence[0] != error_class:
            raise ValueError(f"{vector_id}: precedence differs from taxonomy")
        first = apply_mutations(adapter, seed, vector.get("mutations"))
        second = apply_mutations(adapter, seed, vector.get("mutations"))
        if first != second:
            raise ValueError(f"{vector_id}: mutation generation is non-deterministic")
        rows.append({"id": vector_id, "bytes": first, "expected_class": error_class, "expected_boundary": expect.get("boundary"), "precedence": precedence})
    return seed, rows, ranks
