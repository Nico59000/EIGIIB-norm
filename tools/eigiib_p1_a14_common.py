"""Strict carriers and registered constants for P1-A14."""
from __future__ import annotations

from eigiib_p1_a13_common import (
    CborTag,
    canonical_json,
    confined,
    data_carrier,
    decode_b64,
    decode_cbor,
    encode_b64,
    encode_cbor,
    exact_keys,
    identity,
    strict_json,
)

STANDARD = "EIGIIB-P1-A14-1.0"
PROFILE = "registered-advisory-remediation-fixed-release-v1"
POLICY_TYPE = "application/vnd.eigiib.remediation-control-policy+json"
ADVISORY_TYPE = "application/vnd.eigiib.security-advisory+json"
REMEDIATION_TYPE = "application/vnd.eigiib.remediation-lineage+json"
FIXED_RELEASE_TYPE = "application/vnd.eigiib.fixed-release+json"
CANDIDATE_TYPE = "application/vnd.eigiib.fixed-release-candidate+json"
ROUTES = ["reference-python-openssl", "independent-go-stdlib", "external-go-cose"]

__all__ = [
    "CborTag", "canonical_json", "confined", "data_carrier", "decode_b64",
    "decode_cbor", "encode_b64", "encode_cbor", "exact_keys", "identity",
    "strict_json", "STANDARD", "PROFILE", "POLICY_TYPE", "ADVISORY_TYPE",
    "REMEDIATION_TYPE", "FIXED_RELEASE_TYPE", "CANDIDATE_TYPE", "ROUTES",
]
