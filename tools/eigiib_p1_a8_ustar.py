"""Closed byte-exact USTAR encoder and parser for P1-A8."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

BLOCK = 512


def _octal(value: int, width: int) -> bytes:
    if value < 0:
        raise ValueError("negative USTAR numeric field")
    digits = format(value, "o")
    if len(digits) > width - 1:
        raise ValueError("USTAR numeric field overflow")
    return ("0" * (width - 1 - len(digits)) + digits).encode("ascii") + b"\0"


def _split_name(path: str) -> tuple[bytes, bytes]:
    raw = path.encode("ascii")
    if len(raw) <= 100:
        return raw, b""
    for index in range(len(raw) - 1, -1, -1):
        if raw[index:index + 1] != b"/":
            continue
        prefix, name = raw[:index], raw[index + 1:]
        if prefix and name and len(prefix) <= 155 and len(name) <= 100:
            return name, prefix
    raise ValueError(f"path does not fit USTAR name/prefix fields: {path}")


def header(path: str, mode: int, size: int) -> bytes:
    name, prefix = _split_name(path)
    block = bytearray(BLOCK)
    block[0:len(name)] = name
    block[100:108] = _octal(mode, 8)
    block[108:116] = _octal(0, 8)
    block[116:124] = _octal(0, 8)
    block[124:136] = _octal(size, 12)
    block[136:148] = _octal(0, 12)
    block[148:156] = b"        "
    block[156:157] = b"0"
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    block[345:345 + len(prefix)] = prefix
    checksum = sum(block)
    checksum_digits = format(checksum, "06o").encode("ascii")
    if len(checksum_digits) != 6:
        raise ValueError("USTAR checksum overflow")
    block[148:156] = checksum_digits + b"\0 "
    return bytes(block)


def build(entries: Iterable[tuple[str, int, bytes]]) -> bytes:
    out = bytearray()
    previous = ""
    for path, mode, data in entries:
        if path <= previous:
            raise ValueError("USTAR entries must be strictly path-sorted")
        previous = path
        out.extend(header(path, mode, len(data)))
        out.extend(data)
        remainder = len(data) % BLOCK
        if remainder:
            out.extend(b"\0" * (BLOCK - remainder))
    out.extend(b"\0" * (2 * BLOCK))
    return bytes(out)


def _parse_octal(field: bytes, label: str) -> int:
    if not field.endswith(b"\0"):
        raise ValueError(f"{label} is not NUL-terminated octal")
    body = field[:-1]
    if not body or any(ch < 48 or ch > 55 for ch in body):
        raise ValueError(f"{label} is not closed-profile octal")
    return int(body, 8)


@dataclass(frozen=True)
class ParsedEntry:
    path: str
    mode: int
    data: bytes


def parse(raw: bytes) -> list[ParsedEntry]:
    if len(raw) < 2 * BLOCK or len(raw) % BLOCK:
        raise ValueError("USTAR archive size is not block-aligned")
    entries: list[ParsedEntry] = []
    offset = 0
    previous = ""
    while offset + 2 * BLOCK <= len(raw):
        block = raw[offset:offset + BLOCK]
        if block == b"\0" * BLOCK:
            if raw[offset:] != b"\0" * (len(raw) - offset):
                raise ValueError("USTAR trailer contains nonzero bytes")
            if len(raw) - offset != 2 * BLOCK:
                raise ValueError("USTAR trailer must contain exactly two blocks")
            return entries
        if block[257:263] != b"ustar\0" or block[263:265] != b"00":
            raise ValueError("USTAR magic/version differs")
        if block[156:157] != b"0":
            raise ValueError("USTAR entry is not a regular file")
        if any(block[start:end].rstrip(b"\0") for start, end in ((265, 297), (297, 329), (329, 337), (337, 345))):
            raise ValueError("USTAR owner/group/device fields differ")
        copy = bytearray(block)
        stored_checksum = block[148:156]
        if len(stored_checksum) != 8 or stored_checksum[6:8] != b"\0 ":
            raise ValueError("USTAR checksum field differs")
        checksum_body = stored_checksum[:6]
        if any(ch < 48 or ch > 55 for ch in checksum_body):
            raise ValueError("USTAR checksum is not octal")
        copy[148:156] = b"        "
        if int(checksum_body, 8) != sum(copy):
            raise ValueError("USTAR checksum mismatch")
        name = block[0:100].split(b"\0", 1)[0]
        prefix = block[345:500].split(b"\0", 1)[0]
        try:
            path = ((prefix + b"/") if prefix else b"") + name
            path_text = path.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("USTAR path is not ASCII") from exc
        if not path_text or path_text <= previous:
            raise ValueError("USTAR paths are not strictly sorted")
        previous = path_text
        mode = _parse_octal(block[100:108], "mode")
        uid = _parse_octal(block[108:116], "uid")
        gid = _parse_octal(block[116:124], "gid")
        size = _parse_octal(block[124:136], "size")
        mtime = _parse_octal(block[136:148], "mtime")
        if mode not in {0o644, 0o755} or uid != 0 or gid != 0 or mtime != 0:
            raise ValueError("USTAR metadata differs from closed profile")
        data_start = offset + BLOCK
        data_end = data_start + size
        if data_end > len(raw):
            raise ValueError("USTAR entry exceeds archive")
        data = raw[data_start:data_end]
        padded_end = data_start + ((size + BLOCK - 1) // BLOCK) * BLOCK
        if raw[data_end:padded_end] != b"\0" * (padded_end - data_end):
            raise ValueError("USTAR data padding is nonzero")
        entries.append(ParsedEntry(path_text, mode, data))
        offset = padded_end
    raise ValueError("USTAR archive is missing its exact trailer")
