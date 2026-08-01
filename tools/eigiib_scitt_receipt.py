#!/usr/bin/env python3
"""Verify EIGIIB P1-A3 SCITT receipt-bound registration capsules.

P1-A3 verifies a SCITT Signed Statement that binds one exact P1-A2 bundle,
then verifies one RFC9942/RFC9162_SHA256 inclusion Receipt against a supplied
Transparency Service Ed25519 public key.

It does not establish trust in either public key, global append-only
consistency, cross-view convergence, trusted registration time, registration
policy correctness, or EIGIIB claim truth.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-P1-A3-1.0"
PROFILE_ID = "scitt-p1-a2-receipt-v1"
EXTERNAL_SPECS = ["scitt-rfc9943", "cose-receipts-rfc9942", "scitt-scrapi-11"]
P1A2_STANDARD = "EIGIIB-P1-A2-1.0"
P1A2_PROFILE = "sigstore-p1-a1-dsse-bundle-v1"

SCITT_STATEMENT_MEDIA = "application/scitt-statement+cose"
SCITT_RECEIPT_MEDIA = "application/scitt-receipt+cose"
P1A2_MEDIA = "application/vnd.dev.sigstore.bundle.v0.3+json"
SCRAPI_PROFILE = "draft-ietf-scitt-scrapi-11"

ALG_EDDSA = -8
VDS_RFC9162_SHA256 = 1
COSE_TAG_SIGN1 = 18
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ISSUER_ID = "https://eigiib.example/p1-a3/issuer"
TS_ID = "https://eigiib.example/p1-a3/transparency-service"

BOUNDARIES = [
    "receipt-signature-valid-does-not-imply-trusted-transparency-service",
    "inclusion-proof-valid-does-not-imply-global-append-only-consistency",
    "receipt-bound-registration-does-not-imply-eigiib-claim-truth",
    "location-header-does-not-imply-receipt-authenticity",
    "registration-http-status-does-not-imply-persistence-without-receipt",
    "receipt-registration-does-not-imply-e11-trusted-time",
    "single-receipt-does-not-imply-e6-cross-view-convergence",
    "scitt-registration-does-not-imply-registration-policy-correctness",
    "p1-a3-fixture-does-not-imply-production-transparency-service",
]

TOP_FIELDS = {
    "standard", "profile", "external_specs", "trust_scope", "registration",
    "signedStatement", "receipt", "binding", "claimBoundary",
}
REG_FIELDS = {
    "apiProfile", "transcriptMode", "method", "resource", "status", "location",
    "requestMediaType", "receiptMediaType",
}
SIGNED_FIELDS = {"encoding", "data", "identity", "issuerKeySpki"}
RECEIPT_FIELDS = {"encoding", "data", "identity", "transparencyServiceKeySpki"}
BIND_FIELDS = {"p1A2Bundle", "vds", "vdsId", "proofType", "treeSize", "leafIndex"}
BOUNDARY_FIELDS = {
    "authority", "receiptSignatureValidity", "inclusionProofValidity",
    "registrationEvidence", "doesNotImply",
}
IDENTITY_FIELDS = {"algorithm", "digest", "bytes"}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


@dataclass
class CborTag:
    tag: int
    value: Any


class CborError(ValueError):
    pass


def strict_json_loads(raw: bytes, code: str = "P1A3.JSON") -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=hook,
            parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"non-finite JSON number: {x}")),
        )
    except Exception as exc:
        raise ValueError(f"{code}: {exc}") from exc


def identity(raw: bytes) -> dict[str, Any]:
    return {"algorithm": "sha256", "digest": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def valid_identity(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and set(obj) == IDENTITY_FIELDS
        and obj.get("algorithm") == "sha256"
        and isinstance(obj.get("digest"), str)
        and len(obj["digest"]) == 64
        and all(c in "0123456789abcdef" for c in obj["digest"])
        and isinstance(obj.get("bytes"), int)
        and not isinstance(obj.get("bytes"), bool)
        and obj["bytes"] > 0
    )


def canonical_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_canonical_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("base64 value must be a non-empty string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64") from exc
    if canonical_b64(decoded) != value:
        raise ValueError("non-canonical base64")
    return decoded


def _cbor_head(major: int, n: int) -> bytes:
    if n < 0:
        raise CborError("negative length")
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 2**32:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 2**64:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise CborError("integer too large")


def cbor_encode(obj: Any) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if isinstance(obj, int) and not isinstance(obj, bool):
        return _cbor_head(0, obj) if obj >= 0 else _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(obj, list):
        return _cbor_head(4, len(obj)) + b"".join(cbor_encode(v) for v in obj)
    if isinstance(obj, dict):
        items: list[tuple[bytes, bytes]] = []
        for key, value in obj.items():
            ek = cbor_encode(key)
            items.append((ek, cbor_encode(value)))
        items.sort(key=lambda kv: (len(kv[0]), kv[0]))
        return _cbor_head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(obj, CborTag):
        return _cbor_head(6, obj.tag) + cbor_encode(obj.value)
    raise CborError(f"unsupported CBOR value type: {type(obj).__name__}")


def cbor_decode(raw: bytes) -> Any:
    view = memoryview(raw)
    pos = 0

    def readn(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(view):
            raise CborError("truncated CBOR")
        out = bytes(view[pos:pos+n])
        pos += n
        return out

    def ai_value(ai: int) -> int:
        if ai < 24:
            return ai
        if ai == 24:
            return readn(1)[0]
        if ai == 25:
            return int.from_bytes(readn(2), "big")
        if ai == 26:
            return int.from_bytes(readn(4), "big")
        if ai == 27:
            return int.from_bytes(readn(8), "big")
        raise CborError("indefinite or reserved CBOR encoding is not allowed")

    def decode_one() -> Any:
        nonlocal pos
        if pos >= len(view):
            raise CborError("truncated CBOR")
        initial = view[pos]
        pos += 1
        major, ai = initial >> 5, initial & 31

        if major == 7:
            if ai == 20:
                return False
            if ai == 21:
                return True
            if ai == 22:
                return None
            raise CborError("floating-point/simple values are not supported by P1-A3")

        n = ai_value(ai)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return readn(n)
        if major == 3:
            try:
                return readn(n).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CborError("invalid CBOR UTF-8 text") from exc
        if major == 4:
            return [decode_one() for _ in range(n)]
        if major == 5:
            out: dict[Any, Any] = {}
            for _ in range(n):
                key = decode_one()
                if key in out:
                    raise CborError("duplicate CBOR map key")
                out[key] = decode_one()
            return out
        if major == 6:
            return CborTag(n, decode_one())
        raise CborError("unsupported CBOR major type")

    result = decode_one()
    if pos != len(view):
        raise CborError("trailing bytes after CBOR item")
    return result


def decode_profile_cbor(raw: bytes, what: str) -> Any:
    obj = cbor_decode(raw)
    if cbor_encode(obj) != raw:
        raise CborError(f"{what} is not in the P1-A3 deterministic CBOR profile")
    return obj


def public_key_der(public_key: Path, openssl: str = "openssl") -> bytes:
    cp = subprocess.run(
        [openssl, "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        raise ValueError("public key cannot be decoded by OpenSSL")
    der = cp.stdout
    if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        raise ValueError("public key is not Ed25519 SubjectPublicKeyInfo")
    return der


def verify_ed25519(public_key: Path, message: bytes, signature: bytes, openssl: str = "openssl") -> bool:
    with tempfile.TemporaryDirectory(prefix="eigiib-p1a3-") as td:
        msg = Path(td) / "message.bin"
        sig = Path(td) / "signature.bin"
        msg.write_bytes(message)
        sig.write_bytes(signature)
        cp = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
             "-rawin", "-in", str(msg), "-sigfile", str(sig)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return cp.returncode == 0


def cose_sig_structure(protected: bytes, payload: bytes) -> bytes:
    return cbor_encode(["Signature1", protected, b"", payload])


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def inclusion_root(entry: bytes, tree_size: int, leaf_index: int, path: list[bytes]) -> bytes:
    if tree_size <= 0:
        raise ValueError("tree size must be positive")
    if leaf_index < 0 or leaf_index >= tree_size:
        raise ValueError("leaf index outside tree")
    r = leaf_hash(entry)
    fn = leaf_index
    sn = tree_size - 1
    for sibling in path:
        if not isinstance(sibling, bytes) or len(sibling) != 32:
            raise ValueError("inclusion path hashes must be 32 bytes")
        if sn == 0:
            raise ValueError("inclusion path has extra node")
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(sibling, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion path is incomplete")
    return r


def _parse_sign1(raw: bytes, what: str) -> tuple[bytes, dict[Any, Any], Any, bytes]:
    obj = decode_profile_cbor(raw, what)
    if not isinstance(obj, CborTag) or obj.tag != COSE_TAG_SIGN1:
        raise ValueError(f"{what}: expected tagged COSE_Sign1")
    arr = obj.value
    if not isinstance(arr, list) or len(arr) != 4:
        raise ValueError(f"{what}: COSE_Sign1 must contain four array items")
    protected, unprotected, payload, signature = arr
    if not isinstance(protected, bytes):
        raise ValueError(f"{what}: protected header must be bstr")
    protected_map = decode_profile_cbor(protected, f"{what} protected header")
    if not isinstance(protected_map, dict):
        raise ValueError(f"{what}: protected header must decode to map")
    if not isinstance(unprotected, dict):
        raise ValueError(f"{what}: unprotected header must be map")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError(f"{what}: Ed25519 signature must be 64 bytes")
    return protected, unprotected, payload, signature


def _kid_for_der(der: bytes) -> bytes:
    return hashlib.sha256(der).digest()


def _subject_for_p1a2(raw: bytes) -> str:
    return "urn:eigiib:p1-a2:" + hashlib.sha256(raw).hexdigest()


def _validate_p1a2_shape(raw: bytes) -> dict[str, Any]:
    obj = strict_json_loads(raw, "P1A3.P1A2.PARSE")
    if not isinstance(obj, dict):
        raise ValueError("P1A3.P1A2.TYPE: P1-A2 root must be object")
    if obj.get("standard") != P1A2_STANDARD or obj.get("profile") != P1A2_PROFILE:
        raise ValueError("P1A3.P1A2.CONST: P1-A2 standard/profile mismatch")
    return obj


def _validate_signed_statement(
    raw: bytes,
    p1a2_raw: bytes,
    issuer_public_key: Path,
    openssl: str,
) -> tuple[bytes, dict[str, Any]]:
    protected, unprotected, payload, signature = _parse_sign1(raw, "SCITT Signed Statement")
    if unprotected != {}:
        raise ValueError("P1A3.STATEMENT.UNPROTECTED: registered Signed Statement must have empty unprotected header")
    if not isinstance(payload, bytes):
        raise ValueError("P1A3.STATEMENT.PAYLOAD: attached CBOR digest payload required")
    pmap = decode_profile_cbor(protected, "SCITT Signed Statement protected header")
    der = public_key_der(issuer_public_key, openssl)
    subject = _subject_for_p1a2(p1a2_raw)
    expected = {
        1: ALG_EDDSA,
        3: "application/cbor",
        4: _kid_for_der(der),
        15: {1: ISSUER_ID, 2: subject},
        16: SCITT_STATEMENT_MEDIA,
    }
    if pmap != expected:
        raise ValueError("P1A3.STATEMENT.HEADER: protected header does not match P1-A3 profile")
    digest_payload = decode_profile_cbor(payload, "P1-A2 digest payload")
    expected_payload = {
        "mediaType": P1A2_MEDIA,
        "sha256": hashlib.sha256(p1a2_raw).digest(),
        "bytes": len(p1a2_raw),
    }
    if digest_payload != expected_payload:
        raise ValueError("P1A3.STATEMENT.BINDING: Signed Statement payload does not bind exact P1-A2 bundle")
    if not verify_ed25519(issuer_public_key, cose_sig_structure(protected, payload), signature, openssl):
        raise ValueError("P1A3.STATEMENT.SIGNATURE: invalid Signed Statement signature")
    return der, {"subject": subject, "payload": payload}


def _validate_receipt(
    raw: bytes,
    signed_statement_raw: bytes,
    subject: str,
    ts_public_key: Path,
    openssl: str,
) -> tuple[bytes, int, int, bytes]:
    protected, unprotected, payload, signature = _parse_sign1(raw, "SCITT Receipt")
    if payload is not None:
        raise ValueError("P1A3.RECEIPT.PAYLOAD: receipt payload must be detached")
    der = public_key_der(ts_public_key, openssl)
    pmap = decode_profile_cbor(protected, "SCITT Receipt protected header")
    expected = {
        1: ALG_EDDSA,
        4: _kid_for_der(der),
        15: {1: TS_ID, 2: subject},
        16: SCITT_RECEIPT_MEDIA,
        395: VDS_RFC9162_SHA256,
    }
    if pmap != expected:
        raise ValueError("P1A3.RECEIPT.HEADER: protected header does not match P1-A3 profile")
    if set(unprotected) != {396} or not isinstance(unprotected.get(396), dict):
        raise ValueError("P1A3.RECEIPT.VDP: receipt must contain only VDP inclusion proof material")
    proofs = unprotected[396]
    if set(proofs) != {-1} or not isinstance(proofs[-1], list) or len(proofs[-1]) != 1:
        raise ValueError("P1A3.RECEIPT.PROOF: exactly one inclusion proof is required")
    proof_raw = proofs[-1][0]
    if not isinstance(proof_raw, bytes):
        raise ValueError("P1A3.RECEIPT.PROOF: inclusion proof must be bstr")
    proof = decode_profile_cbor(proof_raw, "RFC9162 inclusion proof")
    if (
        not isinstance(proof, list) or len(proof) != 3
        or not isinstance(proof[0], int) or isinstance(proof[0], bool)
        or not isinstance(proof[1], int) or isinstance(proof[1], bool)
        or not isinstance(proof[2], list)
    ):
        raise ValueError("P1A3.RECEIPT.PROOF: invalid RFC9162 inclusion proof shape")
    tree_size, leaf_index, path = proof
    root = inclusion_root(signed_statement_raw, tree_size, leaf_index, path)
    if not verify_ed25519(ts_public_key, cose_sig_structure(protected, root), signature, openssl):
        raise ValueError("P1A3.RECEIPT.SIGNATURE: invalid receipt signature for computed inclusion root")
    return der, tree_size, leaf_index, root


def result(findings: list[Finding], states: dict[str, str]) -> dict[str, Any]:
    out = {
        "tool": "eigiib-scitt-receipt",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if findings else "conformant",
        "upstream_p1a2_result": states.get("upstream_p1a2_result", "not-evaluated"),
        "signed_statement_signature_result": states.get("signed_statement_signature_result", "not-evaluated"),
        "receipt_signature_result": states.get("receipt_signature_result", "not-evaluated"),
        "inclusion_result": states.get("inclusion_result", "not-evaluated"),
        "registration_evidence_result": states.get("registration_evidence_result", "not-evaluated"),
        "trust_result": "not-evaluated-by-p1-a3",
        "append_only_result": "not-evaluated-by-p1-a3",
        "cross_view_result": "not-evaluated-by-p1-a3",
        "time_result": "not-evaluated-by-p1-a3",
        "findings": [asdict(f) for f in sorted(findings)],
    }
    if findings:
        for k in (
            "signed_statement_signature_result", "receipt_signature_result",
            "inclusion_result", "registration_evidence_result",
        ):
            if out[k] in {"valid", "verified", "receipt-bound"}:
                out[k] = "not-evaluated"
    return out


def validate_capsule(
    obj: Any,
    p1a2_raw: bytes,
    issuer_public_key: Path,
    ts_public_key: Path,
    openssl: str = "openssl",
) -> dict[str, Any]:
    findings: list[Finding] = []
    states: dict[str, str] = {"upstream_p1a2_result": "shape-conformant"}

    def add(code: str, path: str, message: str) -> None:
        findings.append(Finding("error", code, path, message))

    try:
        _validate_p1a2_shape(p1a2_raw)
    except ValueError as exc:
        add("P1A3.P1A2.INVALID", "P1-A2", str(exc))
        states["upstream_p1a2_result"] = "invalid"

    if not isinstance(obj, dict):
        add("P1A3.CAPSULE.TYPE", "", "capsule root must be object")
        return result(findings, states)
    if set(obj) != TOP_FIELDS:
        add("P1A3.CAPSULE.FIELD", "", "capsule fields do not match P1-A3")
    constants = {
        "standard": STANDARD,
        "profile": PROFILE_ID,
        "external_specs": EXTERNAL_SPECS,
        "trust_scope": "supplied-public-keys-only",
    }
    for key, expected in constants.items():
        if obj.get(key) != expected:
            add("P1A3.CAPSULE.CONST", key, f"{key} does not match P1-A3")

    reg = obj.get("registration")
    if not isinstance(reg, dict) or set(reg) != REG_FIELDS:
        add("P1A3.REG.FIELD", "registration", "registration transcript fields do not match P1-A3")
        reg = {}
    else:
        expected_reg = {
            "apiProfile": SCRAPI_PROFILE,
            "transcriptMode": "fixture-no-network",
            "method": "POST",
            "resource": "/entries",
            "status": 201,
            "requestMediaType": SCITT_STATEMENT_MEDIA,
            "receiptMediaType": SCITT_RECEIPT_MEDIA,
        }
        for key, expected in expected_reg.items():
            if reg.get(key) != expected:
                add("P1A3.REG.VALUE", f"registration.{key}", f"{key} does not match P1-A3 profile")
        loc = reg.get("location")
        if not isinstance(loc, str) or not loc.startswith("https://transparency.example/entries/"):
            add("P1A3.REG.LOCATION", "registration.location", "fixture Location must be an HTTPS transparency.example entry URI")

    signed = obj.get("signedStatement")
    signed_raw = None
    if not isinstance(signed, dict) or set(signed) != SIGNED_FIELDS:
        add("P1A3.STATEMENT.FIELD", "signedStatement", "signedStatement fields do not match P1-A3")
        signed = {}
    else:
        if signed.get("encoding") != "base64-cbor":
            add("P1A3.STATEMENT.ENCODING", "signedStatement.encoding", "encoding must be base64-cbor")
        try:
            signed_raw = decode_canonical_b64(signed.get("data"))
        except ValueError as exc:
            add("P1A3.STATEMENT.BASE64", "signedStatement.data", str(exc))
        if not valid_identity(signed.get("identity")):
            add("P1A3.STATEMENT.IDENTITY", "signedStatement.identity", "invalid Signed Statement identity")
        if not valid_identity(signed.get("issuerKeySpki")):
            add("P1A3.STATEMENT.KEY_IDENTITY", "signedStatement.issuerKeySpki", "invalid issuer key identity")

    receipt = obj.get("receipt")
    receipt_raw = None
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        add("P1A3.RECEIPT.FIELD", "receipt", "receipt fields do not match P1-A3")
        receipt = {}
    else:
        if receipt.get("encoding") != "base64-cbor":
            add("P1A3.RECEIPT.ENCODING", "receipt.encoding", "encoding must be base64-cbor")
        try:
            receipt_raw = decode_canonical_b64(receipt.get("data"))
        except ValueError as exc:
            add("P1A3.RECEIPT.BASE64", "receipt.data", str(exc))
        if not valid_identity(receipt.get("identity")):
            add("P1A3.RECEIPT.IDENTITY", "receipt.identity", "invalid receipt identity")
        if not valid_identity(receipt.get("transparencyServiceKeySpki")):
            add("P1A3.RECEIPT.KEY_IDENTITY", "receipt.transparencyServiceKeySpki", "invalid TS key identity")

    binding = obj.get("binding")
    if not isinstance(binding, dict) or set(binding) != BIND_FIELDS:
        add("P1A3.BINDING.FIELD", "binding", "binding fields do not match P1-A3")
        binding = {}
    else:
        if not valid_identity(binding.get("p1A2Bundle")):
            add("P1A3.BINDING.P1A2", "binding.p1A2Bundle", "invalid P1-A2 identity")
        if binding.get("vds") != "RFC9162_SHA256" or binding.get("vdsId") != 1 or binding.get("proofType") != "inclusion":
            add("P1A3.BINDING.VDS", "binding", "P1-A3 supports only RFC9162_SHA256 inclusion receipts")
        if not isinstance(binding.get("treeSize"), int) or isinstance(binding.get("treeSize"), bool) or binding.get("treeSize", 0) <= 0:
            add("P1A3.BINDING.TREE", "binding.treeSize", "treeSize must be positive integer")
        if not isinstance(binding.get("leafIndex"), int) or isinstance(binding.get("leafIndex"), bool) or binding.get("leafIndex", -1) < 0:
            add("P1A3.BINDING.LEAF", "binding.leafIndex", "leafIndex must be non-negative integer")

    boundary = obj.get("claimBoundary")
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_FIELDS:
        add("P1A3.BOUNDARY.FIELD", "claimBoundary", "claimBoundary fields do not match P1-A3")
    else:
        if boundary.get("authority") != "e5":
            add("P1A3.BOUNDARY.AUTHORITY", "claimBoundary.authority", "E5 remains transparency authority")
        if boundary.get("receiptSignatureValidity") != "cryptographic-signature-valid-for-supplied-transparency-service-key":
            add("P1A3.BOUNDARY.RECEIPT", "claimBoundary.receiptSignatureValidity", "receipt signature boundary mismatch")
        if boundary.get("inclusionProofValidity") != "verified-rfc9162-sha256":
            add("P1A3.BOUNDARY.INCLUSION", "claimBoundary.inclusionProofValidity", "inclusion boundary mismatch")
        if boundary.get("registrationEvidence") != "receipt-proves-inclusion-relative-to-supplied-key":
            add("P1A3.BOUNDARY.REGISTRATION", "claimBoundary.registrationEvidence", "registration boundary mismatch")
        if boundary.get("doesNotImply") != BOUNDARIES:
            add("P1A3.BOUNDARY.WEAKENED", "claimBoundary.doesNotImply", "negative implication boundary must match P1-A3 exactly")

    if binding and valid_identity(binding.get("p1A2Bundle")) and binding["p1A2Bundle"] != identity(p1a2_raw):
        add("P1A3.BINDING.P1A2_MISMATCH", "binding.p1A2Bundle", "P1-A2 identity does not match exact source bytes")

    issuer_der = ts_der = None
    try:
        issuer_der = public_key_der(issuer_public_key, openssl)
    except (OSError, ValueError) as exc:
        add("P1A3.ISSUER_KEY.INVALID", str(issuer_public_key), str(exc))
    try:
        ts_der = public_key_der(ts_public_key, openssl)
    except (OSError, ValueError) as exc:
        add("P1A3.TS_KEY.INVALID", str(ts_public_key), str(exc))

    subject = None
    observed_tree = observed_leaf = None
    if signed_raw is not None and issuer_der is not None:
        if valid_identity(signed.get("identity")) and signed["identity"] != identity(signed_raw):
            add("P1A3.STATEMENT.IDENTITY_MISMATCH", "signedStatement.identity", "Signed Statement identity mismatch")
        if valid_identity(signed.get("issuerKeySpki")) and signed["issuerKeySpki"] != identity(issuer_der):
            add("P1A3.STATEMENT.KEY_MISMATCH", "signedStatement.issuerKeySpki", "issuer key identity mismatch")
        try:
            _, meta = _validate_signed_statement(signed_raw, p1a2_raw, issuer_public_key, openssl)
            subject = meta["subject"]
            states["signed_statement_signature_result"] = "valid"
        except (OSError, ValueError, CborError) as exc:
            add("P1A3.STATEMENT.INVALID", "signedStatement", str(exc))
            states["signed_statement_signature_result"] = "invalid"

    if receipt_raw is not None and ts_der is not None:
        if valid_identity(receipt.get("identity")) and receipt["identity"] != identity(receipt_raw):
            add("P1A3.RECEIPT.IDENTITY_MISMATCH", "receipt.identity", "Receipt identity mismatch")
        if valid_identity(receipt.get("transparencyServiceKeySpki")) and receipt["transparencyServiceKeySpki"] != identity(ts_der):
            add("P1A3.RECEIPT.KEY_MISMATCH", "receipt.transparencyServiceKeySpki", "TS key identity mismatch")
        if signed_raw is not None and subject is not None:
            try:
                _, observed_tree, observed_leaf, _ = _validate_receipt(
                    receipt_raw, signed_raw, subject, ts_public_key, openssl
                )
                states["receipt_signature_result"] = "valid"
                states["inclusion_result"] = "verified"
            except (OSError, ValueError, CborError) as exc:
                add("P1A3.RECEIPT.INVALID", "receipt", str(exc))
                states["receipt_signature_result"] = "invalid"
                states["inclusion_result"] = "invalid"

    if observed_tree is not None and binding:
        if binding.get("treeSize") != observed_tree or binding.get("leafIndex") != observed_leaf:
            add("P1A3.BINDING.PROOF_MISMATCH", "binding", "declared treeSize/leafIndex do not match receipt proof")

    if signed_raw is not None and reg:
        expected_loc = "https://transparency.example/entries/" + hashlib.sha256(signed_raw).hexdigest()
        if reg.get("location") != expected_loc:
            add("P1A3.REG.LOCATION_BINDING", "registration.location", "Location is not bound to exact Signed Statement identity")

    if not findings and states.get("receipt_signature_result") == "valid" and states.get("inclusion_result") == "verified":
        states["registration_evidence_result"] = "receipt-bound"
    return result(findings, states)


def check_repository(root: Path, openssl: str = "openssl") -> dict[str, Any]:
    fixture = root / "tests/fixtures/p1-a3/capsule.json"
    p1a2_file = root / "tests/fixtures/p1-a2/bundle.json"
    issuer_key = root / "tests/fixtures/p1-a3/issuer-public-key.pem"
    ts_key = root / "tests/fixtures/p1-a3/ts-public-key.pem"
    p1a1_file = root / "tests/fixtures/p1-a1/capsule.json"
    p1a2_key = root / "tests/fixtures/p1-a2/public-key.pem"

    for path in (fixture, p1a2_file, issuer_key, ts_key, p1a1_file, p1a2_key):
        if not path.is_file():
            return result([Finding("error", "P1A3.REPO.MISSING", str(path), "required P1-A3 fixture dependency is missing")], {})

    try:
        import eigiib_sigstore_bundle as p1a2
        p1a2_raw = p1a2_file.read_bytes()
        p1a2_obj = p1a2.strict_json_loads(p1a2_raw, "P1A3.UPSTREAM.P1A2")
        upstream = p1a2.validate_capsule(
            p1a2_obj, p1a2_key, p1a1_file.read_bytes(), openssl
        )
        if upstream.get("structural_result") != "conformant" or upstream.get("signature_result") != "valid":
            return result([Finding("error", "P1A3.UPSTREAM.P1A2", str(p1a2_file), "P1-A2 upstream capsule is not conformant and signature-valid")], {"upstream_p1a2_result": "invalid"})
    except Exception as exc:
        return result([Finding("error", "P1A3.UPSTREAM.P1A2", str(p1a2_file), str(exc))], {"upstream_p1a2_result": "invalid"})

    private_markers = ("PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY")
    for path in (root / "tests/fixtures/p1-a3").iterdir():
        if path.is_file():
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            if any(marker in text for marker in private_markers):
                return result([Finding("error", "P1A3.REPO.PRIVATE_KEY", str(path), "private-key material must not be stored in P1-A3 fixtures")], {"upstream_p1a2_result": "conformant"})

    try:
        obj = strict_json_loads(fixture.read_bytes(), "P1A3.REPO.CAPSULE")
    except ValueError as exc:
        return result([Finding("error", "P1A3.REPO.CAPSULE", str(fixture), str(exc))], {"upstream_p1a2_result": "conformant"})

    out = validate_capsule(obj, p1a2_raw, issuer_key, ts_key, openssl)
    out["upstream_p1a2_result"] = "conformant"
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify")
    v.add_argument("capsule", type=Path)
    v.add_argument("--p1-a2", required=True, type=Path)
    v.add_argument("--issuer-key", required=True, type=Path)
    v.add_argument("--ts-key", required=True, type=Path)
    v.add_argument("--openssl", default="openssl")
    v.add_argument("--json", action="store_true")

    c = sub.add_parser("check")
    c.add_argument("root", type=Path, nargs="?", default=Path("."))
    c.add_argument("--openssl", default="openssl")
    c.add_argument("--json", action="store_true")

    args = parser.parse_args()
    if args.command == "verify":
        try:
            obj = strict_json_loads(args.capsule.read_bytes())
            out = validate_capsule(obj, args.p1_a2.read_bytes(), args.issuer_key, args.ts_key, args.openssl)
        except Exception as exc:
            out = result([Finding("error", "P1A3.CLI", str(args.capsule), str(exc))], {})
    else:
        out = check_repository(args.root, args.openssl)

    if getattr(args, "json", False):
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(out["structural_result"])
        for f in out["findings"]:
            print(f"{f['severity']}: {f['code']}: {f['path']}: {f['message']}")
    return 0 if out["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
