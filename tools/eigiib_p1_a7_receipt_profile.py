"""Closed P1-A7.6 Receipt profile and OpenSSL verification."""
from __future__ import annotations
from eigiib_p1_a7_cose_codec import *
from eigiib_p1_a7_receipt_carrier import *
from eigiib_p1_a7_receipt_carrier import _read_carrier
from eigiib_p1_a7_receipt_proof import *
from eigiib_p1_a7_receipt_proof import _proof, _receipt_parts, _root, _sig_structure, _verify

def evaluate(raw: bytes, vector_id: str, openssl: str = "openssl", route: str = ROUTE) -> Result:
    try:
        signed_raw, receipt_raw, key_pem, binding_tree, binding_leaf = _read_carrier(raw)
        _, key_der = parse_public_key_pem(key_pem)
        protected_raw, proof_raw, signature = _receipt_parts(receipt_raw, key_der)
        if identity(signed_raw) != EXPECTED_SIGNED_STATEMENT_IDENTITY:
            raise Reject("receipt.invalid-proof", "receipt-detached-binding")
        proof_tree, proof_leaf, path = _proof(proof_raw)
        if proof_tree != binding_tree or proof_leaf != binding_leaf:
            raise Reject("receipt.invalid-proof", "receipt-coordinates")
        root = _root(signed_raw, proof_tree, proof_leaf, path)
        if not _verify(key_pem, _sig_structure(protected_raw, root), signature, openssl):
            raise Reject("receipt.invalid-proof", "receipt-root")
    except Reject as exc:
        return Result(STANDARD, route, vector_id, False, exc.error_class, exc.boundary)
    except OSError as exc:
        raise RuntimeError(f"OpenSSL route unavailable: {exc}") from exc
    except ValueError:
        return Result(STANDARD, route, vector_id, False, "receipt.invalid-proof", "receipt-carrier")
    return Result(STANDARD, route, vector_id, True, None, "receipt-root")
