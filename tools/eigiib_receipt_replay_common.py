"""Shared contracts for P1-A7.6 Receipt replay."""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A7.6-1.0"
PROFILE = "receipt-detached-proof-root-negative-replay-v1"
TOOL_VERSION = "0.1.0"
ROUTES = ["reference-python-openssl", "independent-go-stdlib", "external-go-cose"]
PLATFORMS = ["ubuntu-24.04", "macos-15", "windows-2025"]
RESULT_KEYS = {"standard", "route", "vector_id", "accepted", "error_class", "boundary"}
CORPUS_PATH = "tests/fixtures/p1-a7/a7.6-receipt-corpus.json"
POSITIVE_ID = "a7-positive-p1-a3-receipt"


def load_adapter(root: Path) -> Any:
    path = root / "tools/eigiib_p1_a7_receipt_adapter.py"
    spec = importlib.util.spec_from_file_location("eigiib_p1_a7_receipt_adapter_replay", path)
    if spec is None or spec.loader is None:
        raise ValueError("unable to load P1-A7.6 reference adapter")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def confined_regular_file(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("path must be a non-empty repository-relative string")
    current = root.resolve()
    for part in Path(relative).parts:
        if part in {"", ".", ".."}:
            raise ValueError("path contains forbidden traversal segment")
        current = current / part
        if current.is_symlink():
            raise ValueError("path contains symlink")
    resolved = current.resolve(strict=True)
    resolved.relative_to(root.resolve())
    if not resolved.is_file():
        raise ValueError("path is not a regular file")
    return resolved


def load_json(adapter: Any, path: Path, label: str) -> Any:
    try:
        return adapter.strict_json_loads(path.read_bytes())
    except Exception as exc:
        raise ValueError(f"{label}: {exc}") from exc


def check_identity(adapter: Any, raw: bytes, declared: Any, label: str) -> None:
    if declared != adapter.identity(raw):
        raise ValueError(f"{label}: identity mismatch")


def taxonomy_ranks(taxonomy: Any) -> dict[str, int]:
    if not isinstance(taxonomy, dict) or not isinstance(taxonomy.get("classes"), list):
        raise ValueError("taxonomy structure differs")
    ranks: dict[str, int] = {}
    seen: set[int] = set()
    for row in taxonomy["classes"]:
        if not isinstance(row, dict):
            raise ValueError("taxonomy class must be object")
        class_id = row.get("id")
        rank = row.get("precedence")
        if not isinstance(class_id, str) or class_id in ranks:
            raise ValueError("taxonomy class IDs must be unique")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1 or rank in seen:
            raise ValueError("taxonomy ranks must be unique positive integers")
        ranks[class_id] = rank
        seen.add(rank)
    if seen != set(range(1, len(ranks) + 1)):
        raise ValueError("taxonomy ranks must be contiguous")
    return ranks
