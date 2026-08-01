"""Dependency-free deterministic CBOR codec and portable primitives for P1-A7.5."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_BREAK = object()

@dataclass(frozen=True)
class CborTag:
    number: int
    value: Any

@dataclass(frozen=True)
class CborMap:
    pairs: tuple[tuple[Any, Any], ...]

    def get(self, key: Any, default: Any=None) -> Any:
        for current, value in self.pairs:
            if current == key:
                return value
        return default

    def has(self, key: Any) -> bool:
        return any((current == key for current, _ in self.pairs))

class Reject(Exception):

    def __init__(self, error_class: str, boundary: str) -> None:
        super().__init__(error_class)
        self.error_class = error_class
        self.boundary = boundary

class CborError(ValueError):
    pass

class Decoder:

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.pos = 0

    def read(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.raw):
            raise CborError('truncated CBOR')
        out = self.raw[self.pos:self.pos + count]
        self.pos += count
        return out

    def argument(self, additional: int) -> int | None:
        if additional < 24:
            return additional
        if additional == 24:
            return self.read(1)[0]
        if additional == 25:
            return int.from_bytes(self.read(2), 'big')
        if additional == 26:
            return int.from_bytes(self.read(4), 'big')
        if additional == 27:
            return int.from_bytes(self.read(8), 'big')
        if additional == 31:
            return None
        raise CborError('reserved CBOR additional information')

    def one(self, *, allow_break: bool=False) -> Any:
        initial = self.read(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            if additional == 31 and allow_break:
                return _BREAK
            raise CborError('unsupported CBOR simple or floating value')
        argument = self.argument(additional)
        if major in {0, 1, 2, 3, 6} and argument is None:
            raise CborError('indefinite encoding is invalid for this CBOR type')
        if major == 0:
            assert argument is not None
            return argument
        if major == 1:
            assert argument is not None
            return -1 - argument
        if major == 2:
            assert argument is not None
            return self.read(argument)
        if major == 3:
            assert argument is not None
            try:
                return self.read(argument).decode('utf-8', errors='strict')
            except UnicodeDecodeError as exc:
                raise CborError('invalid CBOR UTF-8') from exc
        if major == 4:
            items: list[Any] = []
            if argument is None:
                while True:
                    value = self.one(allow_break=True)
                    if value is _BREAK:
                        break
                    items.append(value)
            else:
                for _ in range(argument):
                    items.append(self.one())
            return items
        if major == 5:
            pairs: list[tuple[Any, Any]] = []
            if argument is None:
                while True:
                    key = self.one(allow_break=True)
                    if key is _BREAK:
                        break
                    value = self.one()
                    pairs.append((key, value))
            else:
                for _ in range(argument):
                    pairs.append((self.one(), self.one()))
            encoded_keys: set[bytes] = set()
            for key, _ in pairs:
                key_bytes = encode_cbor(key)
                if key_bytes in encoded_keys:
                    raise CborError('duplicate CBOR map key')
                encoded_keys.add(key_bytes)
            return CborMap(tuple(pairs))
        if major == 6:
            assert argument is not None
            return CborTag(argument, self.one())
        raise CborError(f'unsupported CBOR major type {major}')

def decode_cbor(raw: bytes) -> Any:
    decoder = Decoder(raw)
    value = decoder.one()
    if decoder.pos != len(raw):
        raise CborError('trailing bytes after CBOR item')
    return value

def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise CborError('negative CBOR length')
    if value < 24:
        return bytes([major << 5 | value])
    if value < 256:
        return bytes([major << 5 | 24, value])
    if value < 65536:
        return bytes([major << 5 | 25]) + value.to_bytes(2, 'big')
    if value < 1 << 32:
        return bytes([major << 5 | 26]) + value.to_bytes(4, 'big')
    if value < 1 << 64:
        return bytes([major << 5 | 27]) + value.to_bytes(8, 'big')
    raise CborError('CBOR integer overflow')

def encode_cbor(value: Any, *, canonical_maps: bool=True) -> bytes:
    if value is None:
        return bytes([246])
    if value is False:
        return bytes([244])
    if value is True:
        return bytes([245])
    if isinstance(value, int) and (not isinstance(value, bool)):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode('utf-8')
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b''.join((encode_cbor(item, canonical_maps=canonical_maps) for item in value))
    if isinstance(value, CborMap):
        rows = [(encode_cbor(key, canonical_maps=canonical_maps), encode_cbor(member, canonical_maps=canonical_maps)) for key, member in value.pairs]
        if canonical_maps:
            rows.sort(key=lambda row: (len(row[0]), row[0]))
        return _head(5, len(rows)) + b''.join((key + member for key, member in rows))
    if isinstance(value, dict):
        return encode_cbor(CborMap(tuple(value.items())), canonical_maps=canonical_maps)
    if isinstance(value, CborTag):
        return _head(6, value.number) + encode_cbor(value.value, canonical_maps=canonical_maps)
    raise CborError(f'unsupported CBOR type {type(value)!r}')

def canonical_decode(raw: bytes, boundary: str='cbor') -> Any:
    try:
        value = decode_cbor(raw)
    except CborError as exc:
        raise Reject('cose.invalid-structure', 'cose-structure') from exc
    if encode_cbor(value) != raw:
        raise Reject('cbor.nondeterministic', boundary)
    return value

def map_replace(mapping: CborMap, key: Any, value: Any) -> CborMap:
    pairs = list(mapping.pairs)
    for index, (current, _) in enumerate(pairs):
        if current == key:
            pairs[index] = (key, value)
            return CborMap(tuple(pairs))
    pairs.append((key, value))
    return CborMap(tuple(pairs))

def strict_json_loads(raw: bytes) -> Any:

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f'duplicate JSON member: {key}')
            out[key] = value
        return out
    try:
        return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=hook, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(f'non-finite JSON number: {token}')))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f'invalid JSON: {exc}') from exc

def canonical_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')

def decode_canonical_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError('base64 value must be non-empty string')
    try:
        decoded = base64.b64decode(value.encode('ascii'), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError('invalid base64') from exc
    if canonical_b64(decoded) != value:
        raise ValueError('non-canonical base64')
    return decoded

def identity(raw: bytes) -> dict[str, Any]:
    return {'algorithm': 'sha256', 'digest': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}

def parse_public_key_pem(value: str) -> tuple[bytes, bytes]:
    lines = value.splitlines()
    if len(lines) != 3:
        raise ValueError('public key PEM line count mismatch')
    if lines[0] != '-----BEGIN PUBLIC KEY-----' or lines[2] != '-----END PUBLIC KEY-----':
        raise ValueError('public key PEM boundary mismatch')
    try:
        der = base64.b64decode(lines[1].encode('ascii'), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError('public key PEM body is invalid') from exc
    if len(der) != 44 or not der.startswith(SPKI_PREFIX):
        raise ValueError('public key is not Ed25519 SubjectPublicKeyInfo')
    return (value.encode('utf-8'), der)
