#!/usr/bin/env python3
"""Build and verify EIGIIB P1-A2 Sigstore DSSE bundle capsules.

P1-A2 authenticates the exact P1-A1 Statement bytes against one supplied
out-of-band Ed25519 public key. It does not establish signer trust,
authorization, transparency inclusion, trusted time, or EIGIIB claim truth.
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

import eigiib_in_toto_capsule as p1a1_tool

TOOL_VERSION = "0.1.1"
STANDARD = "EIGIIB-P1-A2-1.0"
PROFILE_ID = "sigstore-p1-a1-dsse-bundle-v1"
EXTERNAL_SPEC_ID = "sigstore-bundle-0.3.2"
P1A1_STANDARD = "EIGIIB-P1-A1-1.0"
P1A1_PROFILE = "in-toto-aggregate-export-v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
CRYPTO_PROFILE = "ed25519-spki-openssl-v1"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
BOUNDARIES = [
    "signature-valid-does-not-imply-trusted-signer",
    "public-key-match-does-not-imply-real-world-identity",
    "trusted-key-does-not-imply-authorized-signer",
    "authenticated-carrier-does-not-imply-eigiib-claim-truth",
    "sigstore-bundle-does-not-imply-transparency-inclusion",
    "absence-of-timestamp-does-not-imply-trusted-time",
    "p1-a2-bundle-does-not-imply-scitt-registration",
]
TOP_FIELDS = {"standard", "profile", "external_spec", "crypto_profile", "trust_scope", "bundle", "binding", "claimBoundary"}
BUNDLE_FIELDS = {"mediaType", "verificationMaterial", "dsseEnvelope"}
VM_FIELDS = {"publicKeyIdentifier"}
ENVELOPE_FIELDS = {"payload", "payloadType", "signatures"}
SIG_FIELDS = {"keyid", "sig"}
BINDING_FIELDS = {"p1A1Statement", "publicKeySpki"}
IDENTITY_FIELDS = {"algorithm", "digest", "bytes"}
BOUNDARY_FIELDS = {"authority", "signatureValidity", "doesNotImply"}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def strict_json_loads(raw: bytes, code: str = "P1A2.JSON") -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=hook, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"non-finite JSON number: {x}")))
    except Exception as exc:
        raise ValueError(f"{code}: {exc}") from exc


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


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
        raise ValueError("base64 value must be non-empty string")
    try:
        decoded = base64.b64decode(value, validate=True)
        encoded = canonical_b64(decoded)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64") from exc
    if encoded != value:
        raise ValueError("non-canonical base64")
    return decoded


def pae(payload_type: bytes, body: bytes) -> bytes:
    return b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" " + payload_type + b" " + str(len(body)).encode("ascii") + b" " + body


def load_p1a1_statement(raw: bytes) -> tuple[dict[str, Any], bytes]:
    obj = strict_json_loads(raw, "P1A2.P1A1.PARSE")
    if not isinstance(obj, dict):
        raise ValueError("P1A2.P1A1.TYPE: P1-A1 capsule root must be object")
    upstream = p1a1_tool.validate_capsule(obj)
    if upstream.get("structural_result") != "conformant":
        codes = ",".join(sorted(str(item.get("code", "")) for item in upstream.get("findings", [])))
        raise ValueError(f"P1A2.P1A1.UPSTREAM: P1-A1 capsule is non-conformant ({codes})")
    required = {
        "standard": P1A1_STANDARD,
        "profile": P1A1_PROFILE,
        "authentication_state": "not-provided-p1-a1",
        "transport_layer": "in-toto-statement-v1",
    }
    for key, expected in required.items():
        if obj.get(key) != expected:
            raise ValueError(f"P1A2.P1A1.CONST: {key} must be {expected}")
    st = obj.get("statement")
    if not isinstance(st, dict) or st.get("_type") != STATEMENT_TYPE:
        raise ValueError("P1A2.P1A1.STATEMENT: invalid P1-A1 Statement")
    return st, canonical_json_bytes(st)


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


def key_hint(der: bytes) -> str:
    return "p1-a2-ed25519-spki-sha256:" + hashlib.sha256(der).hexdigest()


def verify_ed25519(public_key: Path, message: bytes, signature: bytes, openssl: str = "openssl") -> bool:
    with tempfile.TemporaryDirectory(prefix="eigiib-p1a2-") as td:
        msg = Path(td) / "message.bin"
        sig = Path(td) / "signature.bin"
        msg.write_bytes(message)
        sig.write_bytes(signature)
        cp = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key), "-rawin", "-in", str(msg), "-sigfile", str(sig)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return cp.returncode == 0


def assemble_capsule(p1a1_raw: bytes, signature_b64: str, public_key: Path, openssl: str = "openssl") -> dict[str, Any]:
    _, statement_bytes = load_p1a1_statement(p1a1_raw)
    signature = decode_canonical_b64(signature_b64)
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    der = public_key_der(public_key, openssl)
    hint = key_hint(der)
    if not verify_ed25519(public_key, pae(PAYLOAD_TYPE.encode("utf-8"), statement_bytes), signature, openssl):
        raise ValueError("signature does not verify over P1-A1 Statement DSSE PAE")
    return {
        "standard": STANDARD,
        "profile": PROFILE_ID,
        "external_spec": EXTERNAL_SPEC_ID,
        "crypto_profile": CRYPTO_PROFILE,
        "trust_scope": "supplied-public-key-only",
        "bundle": {
            "mediaType": BUNDLE_MEDIA_TYPE,
            "verificationMaterial": {"publicKeyIdentifier": {"hint": hint}},
            "dsseEnvelope": {
                "payload": canonical_b64(statement_bytes),
                "payloadType": PAYLOAD_TYPE,
                "signatures": [{"keyid": hint, "sig": signature_b64}],
            },
        },
        "binding": {
            "p1A1Statement": identity(statement_bytes),
            "publicKeySpki": identity(der),
        },
        "claimBoundary": {
            "authority": "e4",
            "signatureValidity": "cryptographic-signature-valid-for-supplied-public-key",
            "doesNotImply": BOUNDARIES[:],
        },
    }


def result(findings: list[Finding], signature_result: str) -> dict[str, Any]:
    return {
        "tool": "eigiib-sigstore-bundle",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if findings else "conformant",
        "signature_result": signature_result,
        "trust_result": "not-evaluated-by-p1-a2",
        "authorization_result": "not-evaluated-by-p1-a2",
        "transparency_result": "not-provided-p1-a2",
        "time_result": "not-provided-p1-a2",
        "findings": [asdict(f) for f in sorted(findings)],
    }


def validate_capsule(obj: Any, public_key: Path, p1a1_raw: bytes | None = None, openssl: str = "openssl") -> dict[str, Any]:
    findings: list[Finding] = []
    signature_result = "not-evaluated"
    def add(code: str, path: str, message: str) -> None:
        findings.append(Finding("error", code, path, message))

    if not isinstance(obj, dict):
        add("P1A2.CAPSULE.TYPE", "", "capsule root must be object")
        return result(findings, signature_result)
    if set(obj) != TOP_FIELDS:
        add("P1A2.CAPSULE.FIELD", "", "capsule fields do not match P1-A2")
    constants = {
        "standard": STANDARD,
        "profile": PROFILE_ID,
        "external_spec": EXTERNAL_SPEC_ID,
        "crypto_profile": CRYPTO_PROFILE,
        "trust_scope": "supplied-public-key-only",
    }
    for key, expected in constants.items():
        if obj.get(key) != expected:
            add("P1A2.CAPSULE.CONST", key, f"{key} must be {expected}")

    bundle = obj.get("bundle")
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS:
        add("P1A2.BUNDLE.FIELD", "bundle", "bundle fields do not match P1-A2 Sigstore profile")
        return result(findings, signature_result)
    if bundle.get("mediaType") != BUNDLE_MEDIA_TYPE:
        add("P1A2.BUNDLE.MEDIA", "bundle.mediaType", "unexpected Sigstore bundle mediaType")

    vm = bundle.get("verificationMaterial")
    hint = None
    if not isinstance(vm, dict) or set(vm) != VM_FIELDS:
        add("P1A2.BUNDLE.VM", "bundle.verificationMaterial", "P1-A2 requires publicKeyIdentifier only; no tlog/timestamp material")
    else:
        pki = vm.get("publicKeyIdentifier")
        if not isinstance(pki, dict) or set(pki) != {"hint"} or not isinstance(pki.get("hint"), str):
            add("P1A2.BUNDLE.KEY_HINT", "bundle.verificationMaterial.publicKeyIdentifier", "invalid public key hint")
        else:
            hint = pki["hint"]

    env = bundle.get("dsseEnvelope")
    payload = signature = None
    keyid = None
    if not isinstance(env, dict) or set(env) != ENVELOPE_FIELDS:
        add("P1A2.DSSE.FIELD", "bundle.dsseEnvelope", "DSSE envelope fields do not match P1-A2")
    else:
        if env.get("payloadType") != PAYLOAD_TYPE:
            add("P1A2.DSSE.PAYLOAD_TYPE", "bundle.dsseEnvelope.payloadType", "payloadType must be application/vnd.in-toto+json")
        try:
            payload = decode_canonical_b64(env.get("payload"))
        except ValueError as exc:
            add("P1A2.DSSE.PAYLOAD", "bundle.dsseEnvelope.payload", str(exc))
        sigs = env.get("signatures")
        if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict) or set(sigs[0]) != SIG_FIELDS:
            add("P1A2.DSSE.SIGNATURES", "bundle.dsseEnvelope.signatures", "Sigstore P1-A2 requires exactly one DSSE signature")
        else:
            keyid = sigs[0].get("keyid")
            if not isinstance(keyid, str) or not keyid:
                add("P1A2.DSSE.KEYID", "bundle.dsseEnvelope.signatures[0].keyid", "keyid must be non-empty hint")
            try:
                signature = decode_canonical_b64(sigs[0].get("sig"))
                if len(signature) != 64:
                    raise ValueError("Ed25519 signature must be 64 bytes")
            except ValueError as exc:
                add("P1A2.DSSE.SIGNATURE", "bundle.dsseEnvelope.signatures[0].sig", str(exc))

    binding = obj.get("binding")
    if not isinstance(binding, dict) or set(binding) != BINDING_FIELDS:
        add("P1A2.BINDING.FIELD", "binding", "binding fields do not match P1-A2")
        binding = {}
    stmt_ident = binding.get("p1A1Statement")
    key_ident = binding.get("publicKeySpki")
    if not valid_identity(stmt_ident):
        add("P1A2.BINDING.STATEMENT", "binding.p1A1Statement", "invalid Statement identity")
    if not valid_identity(key_ident):
        add("P1A2.BINDING.KEY", "binding.publicKeySpki", "invalid public key identity")

    boundary = obj.get("claimBoundary")
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_FIELDS:
        add("P1A2.BOUNDARY.FIELD", "claimBoundary", "claimBoundary fields do not match P1-A2")
    else:
        if boundary.get("authority") != "e4" or boundary.get("signatureValidity") != "cryptographic-signature-valid-for-supplied-public-key":
            add("P1A2.BOUNDARY.MODE", "claimBoundary", "claim boundary mode mismatch")
        if boundary.get("doesNotImply") != BOUNDARIES:
            add("P1A2.BOUNDARY.WEAKENED", "claimBoundary.doesNotImply", "negative implication boundary must match P1-A2 exactly")

    der = None
    try:
        der = public_key_der(public_key, openssl)
    except (OSError, ValueError) as exc:
        add("P1A2.KEY.INVALID", str(public_key), str(exc))
    if der is not None:
        expected_hint = key_hint(der)
        if hint is not None and hint != expected_hint:
            add("P1A2.KEY.HINT_MISMATCH", "bundle.verificationMaterial.publicKeyIdentifier.hint", "hint does not match supplied public key")
        if keyid is not None and keyid != expected_hint:
            add("P1A2.DSSE.KEYID_MISMATCH", "bundle.dsseEnvelope.signatures[0].keyid", "keyid does not match supplied public key hint")
        actual_key = identity(der)
        if valid_identity(key_ident) and key_ident != actual_key:
            add("P1A2.BINDING.KEY_MISMATCH", "binding.publicKeySpki", "public key binding does not match supplied key")

    if p1a1_raw is None:
        add("P1A2.P1A1.REQUIRED", "source", "exact P1-A1 capsule is required for P1-A2 conformance")

    if payload is not None:
        actual_stmt = identity(payload)
        if valid_identity(stmt_ident) and stmt_ident != actual_stmt:
            add("P1A2.BINDING.STATEMENT_MISMATCH", "binding.p1A1Statement", "Statement identity does not match DSSE payload bytes")
        try:
            statement = strict_json_loads(payload, "P1A2.STATEMENT.PARSE")
            if not isinstance(statement, dict) or statement.get("_type") != STATEMENT_TYPE:
                add("P1A2.STATEMENT.TYPE", "bundle.dsseEnvelope.payload", "payload is not in-toto Statement/v1")
            elif payload != canonical_json_bytes(statement):
                add("P1A2.STATEMENT.NONCANONICAL", "bundle.dsseEnvelope.payload", "payload bytes are not the deterministic P1-A2 Statement serialization")
        except ValueError as exc:
            add("P1A2.STATEMENT.PARSE", "bundle.dsseEnvelope.payload", str(exc))
        if p1a1_raw is not None:
            try:
                _, expected_statement = load_p1a1_statement(p1a1_raw)
                if payload != expected_statement:
                    add("P1A2.P1A1.MISMATCH", "bundle.dsseEnvelope.payload", "DSSE payload differs from exact deterministic P1-A1 Statement serialization")
            except ValueError as exc:
                add("P1A2.P1A1.INVALID", "source", str(exc))

    if payload is not None and signature is not None and der is not None and env.get("payloadType") == PAYLOAD_TYPE:
        try:
            ok = verify_ed25519(public_key, pae(PAYLOAD_TYPE.encode("utf-8"), payload), signature, openssl)
            signature_result = "valid" if ok else "invalid"
            if not ok:
                add("P1A2.SIGNATURE.INVALID", "bundle.dsseEnvelope.signatures[0].sig", "signature does not verify over DSSE PAE")
        except OSError as exc:
            add("P1A2.CRYPTO.UNAVAILABLE", openssl, str(exc))
            signature_result = "unavailable"

    return result(findings, signature_result)


def load_capsule_file(path: Path) -> Any:
    return strict_json_loads(path.read_bytes(), "P1A2.CAPSULE.PARSE")


def self_check(root: Path, openssl: str = "openssl") -> dict[str, Any]:
    cfg_path = root / "conformance/p1-a2-sigstore.json"
    bundle_path = root / "tests/fixtures/p1-a2/bundle.json"
    key_path = root / "tests/fixtures/p1-a2/public-key.pem"
    p1a1_path = root / "tests/fixtures/p1-a1/capsule.json"
    profile_path = root / "conformance/interop-profiles.json"
    findings: list[Finding] = []
    for p in (cfg_path, bundle_path, key_path, p1a1_path, profile_path):
        if not p.is_file():
            findings.append(Finding("error", "P1A2.SELF.MISSING", str(p.relative_to(root)), "required file is missing"))
    fixture_dir = root / "tests/fixtures/p1-a2"
    if fixture_dir.is_dir():
        for p in fixture_dir.iterdir():
            if p.is_file() and ("PRIVATE KEY" in p.read_text(encoding="utf-8", errors="ignore") or p.suffix in {".key", ".p8"}):
                findings.append(Finding("error", "P1A2.SELF.PRIVATE_KEY", str(p.relative_to(root)), "private key material must not be committed"))
    if findings:
        return result(findings, "not-evaluated")
    try:
        cfg = strict_json_loads(cfg_path.read_bytes(), "P1A2.SELF.CONFIG")
        bundle = load_capsule_file(bundle_path)
        profiles = strict_json_loads(profile_path.read_bytes(), "P1A2.SELF.PROFILES")
    except ValueError as exc:
        return result([Finding("error", "P1A2.SELF.PARSE", "", str(exc))], "not-evaluated")
    expected_cfg = {
        "standard": STANDARD,
        "status": "structural-only",
        "profile": PROFILE_ID,
        "external_spec": EXTERNAL_SPEC_ID,
        "bundle_media_type": BUNDLE_MEDIA_TYPE,
        "payload_type": PAYLOAD_TYPE,
        "crypto_profile": CRYPTO_PROFILE,
        "public_key_mode": "out-of-band",
        "transparency_state": "not-provided-p1-a2",
        "timestamp_state": "not-provided-p1-a2",
        "production_bundles": [],
    }
    if cfg != expected_cfg:
        findings.append(Finding("error", "P1A2.SELF.CONFIG", str(cfg_path.relative_to(root)), "structural config differs from P1-A2 contract"))
    vr = validate_capsule(bundle, key_path, p1a1_path.read_bytes(), openssl)
    for item in vr["findings"]:
        findings.append(Finding(**item))
    if vr["signature_result"] != "valid":
        findings.append(Finding("error", "P1A2.SELF.SIGNATURE", str(bundle_path.relative_to(root)), "fixture signature must verify"))
    match = next((p for p in profiles.get("profiles", []) if isinstance(p, dict) and p.get("id") == PROFILE_ID), None)
    required_evidence = {
        "docs/P1-A2-SIGSTORE-SIGNED-BUNDLE-CAPSULE.md",
        "tools/eigiib_sigstore_bundle.py",
        "tests/test_eigiib_sigstore_bundle.py",
        "tests/fixtures/p1-a2/bundle.json",
        "tests/fixtures/p1-a2/public-key.pem",
        "conformance/p1-a2-sigstore.json",
    }
    if not isinstance(match, dict) or match.get("state") != "implemented":
        findings.append(Finding("error", "P1A2.SELF.PROFILE_STATE", "conformance/interop-profiles.json", "M0-A3 Sigstore profile must be implemented"))
    elif not required_evidence.issubset(set(match.get("evidence", []))):
        findings.append(Finding("error", "P1A2.SELF.PROFILE_EVIDENCE", "conformance/interop-profiles.json", "M0-A3 profile evidence does not cover P1-A2 adapter"))
    return result(findings, "valid" if not findings else vr["signature_result"])


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    a = sub.add_parser("assemble")
    a.add_argument("p1a1_capsule")
    a.add_argument("--signature", required=True, help="canonical base64 Ed25519 signature over DSSE PAE")
    a.add_argument("--public-key", required=True)
    a.add_argument("--openssl", default="openssl")
    a.add_argument("-o", "--output")
    v = sub.add_parser("verify")
    v.add_argument("capsule")
    v.add_argument("--public-key", required=True)
    v.add_argument("--p1-a1", required=True)
    v.add_argument("--openssl", default="openssl")
    v.add_argument("--json", action="store_true")
    c = sub.add_parser("check")
    c.add_argument("root", nargs="?", default=".")
    c.add_argument("--openssl", default="openssl")
    c.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.command == "assemble":
        obj = assemble_capsule(Path(args.p1a1_capsule).read_bytes(), args.signature, Path(args.public_key), args.openssl)
        text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0
    if args.command == "verify":
        obj = load_capsule_file(Path(args.capsule))
        raw = Path(args.p1_a1).read_bytes()
        out = validate_capsule(obj, Path(args.public_key), raw, args.openssl)
    else:
        out = self_check(Path(args.root).resolve(), args.openssl)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 1 if out["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
