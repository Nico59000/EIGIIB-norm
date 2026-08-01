"""Strict A7.6 Receipt carrier parsing."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from eigiib_p1_a7_cose_codec import Reject, decode_canonical_b64, identity, strict_json_loads
STANDARD = "EIGIIB-P1-A7.6-1.0"
CARRIER_STANDARD = "EIGIIB-P1-A7.6-CARRIER-1.0"
PROFILE = "receipt-detached-proof-root-negative-replay-v1"
ROUTE = "reference-python-openssl"
COSE_SIGN1_TAG = 18
ALGORITHM_EDDSA = -8
TYPE = "application/scitt-receipt+cose"
ISSUER = "https://eigiib.example/p1-a3/transparency-service"
SUBJECT = "urn:eigiib:p1-a2:dd14c7556ea261cee03c40615368511bf9360e5d7eae764804d7b426f4ed6da4"
VDS_ID = 1
EXPECTED_SIGNED_STATEMENT_IDENTITY = {
    "algorithm": "sha256",
    "bytes": 396,
    "digest": "27c960d31e9afbf454c8bb6dbdd396309b3dec629f58d8f5c87553864e579d81",
}

@dataclass(frozen=True)
class Result:
    standard: str
    route: str
    vector_id: str
    accepted: bool
    error_class: str | None
    boundary: str


def canonical_json(value: Any) -> bytes:
    import json
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _exact_keys(value: Any, names: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == names


def _read_carrier(raw: bytes) -> tuple[bytes, bytes, str, int, int]:
    try:
        document = strict_json_loads(raw)
    except ValueError as exc:
        raise Reject("receipt.invalid-proof", "receipt-carrier") from exc
    if not _exact_keys(document, {"standard", "profile", "binding", "signedStatement", "receipt", "publicKeyPem"}):
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    if document["standard"] != CARRIER_STANDARD or document["profile"] != PROFILE:
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    binding = document["binding"]
    signed = document["signedStatement"]
    receipt = document["receipt"]
    if not _exact_keys(binding, {"treeSize", "leafIndex", "signedStatementIdentity"}):
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    if not _exact_keys(signed, {"data", "identity"}) or not _exact_keys(receipt, {"data", "identity"}):
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    tree_size = binding["treeSize"]
    leaf_index = binding["leafIndex"]
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    try:
        signed_raw = decode_canonical_b64(signed["data"])
        receipt_raw = decode_canonical_b64(receipt["data"])
    except ValueError as exc:
        raise Reject("receipt.invalid-proof", "receipt-carrier") from exc
    if signed["identity"] != identity(signed_raw) or receipt["identity"] != identity(receipt_raw):
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    if binding["signedStatementIdentity"] != EXPECTED_SIGNED_STATEMENT_IDENTITY:
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    key_pem = document["publicKeyPem"]
    if not isinstance(key_pem, str):
        raise Reject("receipt.invalid-proof", "receipt-carrier")
    return signed_raw, receipt_raw, key_pem, tree_size, leaf_index


