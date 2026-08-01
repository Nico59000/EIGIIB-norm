"""A7.6 Receipt COSE, proof and detached-root verification."""
from __future__ import annotations
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from eigiib_p1_a7_cose_codec import CborMap, CborTag, CborError, Reject, canonical_decode, decode_cbor, encode_cbor
from eigiib_p1_a7_receipt_carrier import ALGORITHM_EDDSA, COSE_SIGN1_TAG, ISSUER, SUBJECT, TYPE, VDS_ID
def _map_exact(mapping: CborMap, expected: dict[Any, Any]) -> bool:
    return len(mapping.pairs) == len(expected) and all(mapping.has(k) and mapping.get(k) == v for k, v in expected.items())


def _receipt_parts(raw: bytes, key_der: bytes) -> tuple[bytes, bytes, bytes]:
    value = canonical_decode(raw, "receipt-cbor-sign1")
    if not isinstance(value, CborTag) or value.number != COSE_SIGN1_TAG:
        raise Reject("cose.invalid-structure", "receipt-cose-structure")
    if not isinstance(value.value, list) or len(value.value) != 4:
        raise Reject("cose.invalid-structure", "receipt-cose-structure")
    protected_raw, unprotected, payload, signature = value.value
    if not isinstance(protected_raw, bytes) or not isinstance(unprotected, CborMap):
        raise Reject("cose.invalid-structure", "receipt-cose-structure")
    if payload is not None:
        raise Reject("cose.invalid-structure", "receipt-cose-structure")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise Reject("cose.invalid-structure", "receipt-cose-structure")
    try:
        protected = decode_cbor(protected_raw)
    except CborError as exc:
        raise Reject("cose.invalid-structure", "receipt-cose-structure") from exc
    if encode_cbor(protected) != protected_raw:
        raise Reject("cbor.nondeterministic", "receipt-protected-header")
    if not isinstance(protected, CborMap):
        raise Reject("cose.invalid-structure", "receipt-cose-structure")
    expected_headers = {
        1: ALGORITHM_EDDSA,
        4: hashlib.sha256(key_der).digest(),
        15: CborMap(((1, ISSUER), (2, SUBJECT))),
        16: TYPE,
        395: VDS_ID,
    }
    if not _map_exact(protected, expected_headers):
        raise Reject("cose.unsupported-header", "receipt-protected-header")
    if len(unprotected.pairs) != 1 or not unprotected.has(396):
        raise Reject("receipt.invalid-proof", "receipt-proof")
    proof_map = unprotected.get(396)
    if not isinstance(proof_map, CborMap) or len(proof_map.pairs) != 1 or not proof_map.has(-1):
        raise Reject("receipt.invalid-proof", "receipt-proof")
    proofs = proof_map.get(-1)
    if not isinstance(proofs, list) or len(proofs) != 1 or not isinstance(proofs[0], bytes):
        raise Reject("receipt.invalid-proof", "receipt-proof")
    return protected_raw, proofs[0], signature


def _proof(proof_raw: bytes) -> tuple[int, int, list[bytes]]:
    try:
        proof = decode_cbor(proof_raw)
    except CborError as exc:
        raise Reject("receipt.invalid-proof", "receipt-proof") from exc
    if encode_cbor(proof) != proof_raw:
        raise Reject("cbor.nondeterministic", "receipt-proof")
    if not isinstance(proof, list) or len(proof) != 3:
        raise Reject("receipt.invalid-proof", "receipt-proof")
    tree_size, leaf_index, path = proof
    if (
        not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or not isinstance(path, list)
    ):
        raise Reject("receipt.invalid-proof", "receipt-proof")
    if any(not isinstance(item, bytes) or len(item) != 32 for item in path):
        raise Reject("receipt.invalid-proof", "receipt-proof")
    return tree_size, leaf_index, path


def _expected_path_length(tree_size: int, leaf_index: int) -> int:
    if tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size:
        raise Reject("receipt.invalid-proof", "receipt-coordinates")
    count = 0
    size = tree_size
    index = leaf_index
    while size > 1:
        if index % 2 == 1 or index < size - 1:
            count += 1
        index //= 2
        size = (size + 1) // 2
    return count


def _leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _root(entry: bytes, tree_size: int, leaf_index: int, path: list[bytes]) -> bytes:
    if len(path) != _expected_path_length(tree_size, leaf_index):
        raise Reject("receipt.invalid-proof", "receipt-proof")
    current = _leaf_hash(entry)
    index = leaf_index
    size = tree_size
    for sibling in path:
        if index % 2 == 1:
            current = _node_hash(sibling, current)
        else:
            current = _node_hash(current, sibling)
        index //= 2
        size = (size + 1) // 2
    return current


def _sig_structure(protected_raw: bytes, root: bytes) -> bytes:
    return encode_cbor(["Signature1", protected_raw, b"", root])


def _verify(public_key_pem: str, message: bytes, signature: bytes, openssl: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="eigiib-p1-a7-6-") as temporary:
        temp = Path(temporary)
        key = temp / "ts-public-key.pem"
        msg = temp / "sig-structure.cbor"
        sig = temp / "signature.bin"
        key.write_text(public_key_pem, encoding="utf-8", newline="\n")
        msg.write_bytes(message)
        sig.write_bytes(signature)
        completed = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin", "-in", str(msg), "-sigfile", str(sig)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed.returncode == 0


