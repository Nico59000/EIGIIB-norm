"""Strict carriers and deterministic CBOR for P1-A13."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A13-1.0"
PROFILE = "registered-content-revocation-withdrawal-anti-rollback-v1"
POLICY_TYPE = "application/vnd.eigiib.content-control-policy+json"
REVOCATION_TYPE = "application/vnd.eigiib.content-revocation+json"
WITHDRAWAL_TYPE = "application/vnd.eigiib.distribution-withdrawal+json"
OBSERVATION_TYPE = "application/vnd.eigiib.distribution-observation+json"
ROUTES = ["reference-python-openssl", "independent-go-stdlib", "external-go-cose"]


@dataclass(frozen=True)
class CborTag:
    number: int
    value: Any


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def strict_json(raw: bytes) -> Any:
    def hook(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in rows:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out

    return json.loads(raw.decode("utf-8"), object_pairs_hook=hook, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def identity(raw: bytes) -> dict[str, Any]:
    return {"algorithm": "sha256", "bytes": len(raw), "digest": hashlib.sha256(raw).hexdigest()}


def encode_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("base64 carrier")
    raw = base64.b64decode(value.encode("ascii"), validate=True)
    if encode_b64(raw) != value:
        raise ValueError("noncanonical base64")
    return raw


def data_carrier(raw: bytes) -> dict[str, Any]:
    return {"data": encode_b64(raw), "identity": identity(raw)}


def exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def confined(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or relative.startswith("/") or any(part in {"", ".", ".."} for part in relative.split("/")):
        raise ValueError("unsafe path")
    base = root.resolve()
    candidate = (base / relative).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError("path escape")
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError("missing or unsafe file")
    return candidate


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CBOR head")
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + value.to_bytes(8, "big")
    raise ValueError("CBOR integer too large")


def encode_cbor(value: Any) -> bytes:
    if isinstance(value, CborTag):
        return _head(6, value.number) + encode_cbor(value.value)
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode_cbor(item) for item in value)
    if isinstance(value, dict):
        rows = [(encode_cbor(key), encode_cbor(item)) for key, item in value.items()]
        rows.sort(key=lambda row: (len(row[0]), row[0]))
        return _head(5, len(rows)) + b"".join(key + item for key, item in rows)
    raise TypeError(f"unsupported CBOR type: {type(value)!r}")


class _Decoder:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if length < 0 or end > len(self.raw):
            raise ValueError("truncated CBOR")
        out = self.raw[self.offset:end]
        self.offset = end
        return out

    def uint(self, additional: int) -> int:
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in sizes:
            raise ValueError("indefinite or reserved CBOR")
        raw = self.take(sizes[additional])
        value = int.from_bytes(raw, "big")
        if additional == 24 and value < 24:
            raise ValueError("nonminimal CBOR")
        if additional == 25 and value <= 0xFF:
            raise ValueError("nonminimal CBOR")
        if additional == 26 and value <= 0xFFFF:
            raise ValueError("nonminimal CBOR")
        if additional == 27 and value <= 0xFFFFFFFF:
            raise ValueError("nonminimal CBOR")
        return value

    def item(self) -> Any:
        first = self.take(1)[0]
        major, additional = first >> 5, first & 31
        if major in {0, 1}:
            value = self.uint(additional)
            return value if major == 0 else -1 - value
        if major in {2, 3}:
            raw = self.take(self.uint(additional))
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("invalid CBOR UTF-8") from exc
        if major == 4:
            return [self.item() for _ in range(self.uint(additional))]
        if major == 5:
            rows: dict[Any, Any] = {}
            encoded_keys: list[bytes] = []
            for _ in range(self.uint(additional)):
                start = self.offset
                key = self.item()
                encoded = self.raw[start:self.offset]
                if key in rows:
                    raise ValueError("duplicate CBOR map key")
                encoded_keys.append(encoded)
                rows[key] = self.item()
            if encoded_keys != sorted(encoded_keys, key=lambda raw: (len(raw), raw)):
                raise ValueError("nondeterministic CBOR map order")
            return rows
        if major == 6:
            return CborTag(self.uint(additional), self.item())
        if major == 7 and additional in {20, 21, 22}:
            return {20: False, 21: True, 22: None}[additional]
        raise ValueError("unsupported CBOR item")


def decode_cbor(raw: bytes) -> Any:
    decoder = _Decoder(raw)
    value = decoder.item()
    if decoder.offset != len(raw):
        raise ValueError("trailing CBOR")
    if encode_cbor(value) != raw:
        raise ValueError("nondeterministic CBOR")
    return value
