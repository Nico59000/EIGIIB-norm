"""Deterministic A7.6 Receipt mutation operators."""
from __future__ import annotations
import copy
from typing import Any
def _document(adapter: Any, raw: bytes) -> dict[str, Any]:
    value = adapter.strict_json_loads(raw)
    if not isinstance(value, dict):
        raise ValueError("carrier root must be object")
    return value


def _receipt_parts(adapter: Any, document: dict[str, Any]) -> tuple[Any, list[Any]]:
    receipt_raw = adapter.decode_canonical_b64(document["receipt"]["data"])
    value = adapter.decode_cbor(receipt_raw)
    if not isinstance(value, adapter.CborTag) or not isinstance(value.value, list) or len(value.value) != 4:
        raise ValueError("Receipt seed is not tagged COSE_Sign1")
    return value, list(value.value)


def _proof_parts(adapter: Any, members: list[Any]) -> tuple[Any, Any, list[Any], bytes]:
    unprotected = members[1]
    if not isinstance(unprotected, adapter.CborMap):
        raise ValueError("Receipt unprotected header is not map")
    proof_map = unprotected.get(396)
    if not isinstance(proof_map, adapter.CborMap):
        raise ValueError("Receipt proof map missing")
    proofs = proof_map.get(-1)
    if not isinstance(proofs, list) or len(proofs) != 1 or not isinstance(proofs[0], bytes):
        raise ValueError("Receipt proof list differs")
    proof = adapter.decode_cbor(proofs[0])
    if not isinstance(proof, list):
        raise ValueError("Receipt proof is not array")
    return unprotected, proof_map, proof, proofs[0]


def _set_proof(adapter: Any, members: list[Any], proof: list[Any]) -> None:
    proof_raw = adapter.encode_cbor(proof)
    members[1] = adapter.CborMap(((396, adapter.CborMap(((-1, [proof_raw]),))),))


def _write_receipt(adapter: Any, document: dict[str, Any], value: Any, members: list[Any]) -> None:
    raw = adapter.encode_cbor(adapter.CborTag(value.number, members))
    document["receipt"]["data"] = adapter.canonical_b64(raw)


def _refresh(adapter: Any, document: dict[str, Any], name: str) -> None:
    raw = adapter.decode_canonical_b64(document[name]["data"])
    document[name]["identity"] = adapter.identity(raw)


def apply_mutations(adapter: Any, seed: bytes, mutations: Any) -> bytes:
    if not isinstance(mutations, list) or not mutations:
        raise ValueError("mutations must be non-empty array")
    document = _document(adapter, seed)
    for mutation in mutations:
        if not isinstance(mutation, dict):
            raise ValueError("mutation must be object")
        operator = mutation.get("operator")
        if operator == "signed-statement.flip-byte":
            index = mutation.get("index")
            mask = mutation.get("mask")
            raw = bytearray(adapter.decode_canonical_b64(document["signedStatement"]["data"]))
            if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index >= len(raw) or not isinstance(mask, int) or isinstance(mask, bool) or not 1 <= mask <= 255:
                raise ValueError("invalid Signed Statement bit flip")
            raw[index] ^= mask
            document["signedStatement"]["data"] = adapter.canonical_b64(bytes(raw))
            continue
        if operator == "binding.set-coordinates":
            tree_size = mutation.get("treeSize")
            leaf_index = mutation.get("leafIndex")
            if not isinstance(tree_size, int) or isinstance(tree_size, bool) or not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
                raise ValueError("binding coordinates must be integers")
            document["binding"]["treeSize"] = tree_size
            document["binding"]["leafIndex"] = leaf_index
            continue
        if operator == "carrier.refresh-identity":
            name = mutation.get("name")
            if name not in {"signedStatement", "receipt"}:
                raise ValueError("identity refresh target differs")
            _refresh(adapter, document, name)
            continue

        value, members = _receipt_parts(adapter, document)
        if operator == "receipt.set-tag":
            tag = mutation.get("value")
            if not isinstance(tag, int) or isinstance(tag, bool) or tag < 0:
                raise ValueError("Receipt tag must be non-negative integer")
            value = adapter.CborTag(tag, value.value)
            raw = adapter.encode_cbor(value)
            document["receipt"]["data"] = adapter.canonical_b64(raw)
            continue
        if operator == "receipt.embed-current-root":
            signed_raw = adapter.decode_canonical_b64(document["signedStatement"]["data"])
            members[2] = __import__("hashlib").sha256(b"\x00" + signed_raw).digest()
            _write_receipt(adapter, document, value, members)
            continue

        _, _, proof, _ = _proof_parts(adapter, members)
        if operator == "receipt.proof-drop-path":
            if len(proof) < 2:
                raise ValueError("proof lacks coordinates")
            _set_proof(adapter, members, proof[:2])
        elif operator == "receipt.proof-set-coordinates":
            tree_size = mutation.get("treeSize")
            leaf_index = mutation.get("leafIndex")
            if not isinstance(tree_size, int) or isinstance(tree_size, bool) or not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
                raise ValueError("proof coordinates must be integers")
            path = proof[2] if len(proof) >= 3 else []
            _set_proof(adapter, members, [tree_size, leaf_index, path])
        elif operator == "receipt.proof-set-siblings":
            values = mutation.get("siblingsHex")
            if not isinstance(values, list) or any(not isinstance(item, str) or len(item) % 2 for item in values):
                raise ValueError("siblingsHex must be an array of complete hex strings")
            tree_size = proof[0] if len(proof) >= 1 else 1
            leaf_index = proof[1] if len(proof) >= 2 else 0
            _set_proof(adapter, members, [tree_size, leaf_index, [bytes.fromhex(item) for item in values]])
        else:
            raise ValueError(f"unknown mutation operator: {operator!r}")
        _write_receipt(adapter, document, value, members)
    return adapter.canonical_json(document)


