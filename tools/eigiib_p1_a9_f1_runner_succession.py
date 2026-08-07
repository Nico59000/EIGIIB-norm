#!/usr/bin/env python3
"""Validate and select exact append-only P1-A9-F1 runner distributions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

WINDOWS_PLATFORM = "windows-2025"
INVARIANT_TOP_LEVEL = (
    "standard",
    "actions",
    "common",
    "binaryIdentityPolicy",
    "semanticEqualityPolicy",
)
ALLOWED_WINDOWS_DIFF = {"imageVersion", "git"}


def strict_object(path: Path, label: str) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member in {label}: {key}")
            out[key] = value
        return out
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=hook)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _policy_windows(policy: dict[str, Any]) -> dict[str, Any]:
    platforms = policy.get("platforms")
    if not isinstance(platforms, dict):
        raise ValueError("toolchain policy platforms must be an object")
    windows = platforms.get(WINDOWS_PLATFORM)
    if not isinstance(windows, dict):
        raise ValueError("toolchain policy windows-2025 carrier missing")
    return windows


def _validate_policy_transition(previous: dict[str, Any], current: dict[str, Any], expected_changes: list[str]) -> None:
    if set(previous) != set(current):
        raise ValueError("toolchain policy top-level fields changed")
    for field in INVARIANT_TOP_LEVEL:
        if previous.get(field) != current.get(field):
            raise ValueError(f"toolchain policy transition changes invariant field {field}")
    prev_platforms = previous.get("platforms")
    curr_platforms = current.get("platforms")
    if not isinstance(prev_platforms, dict) or not isinstance(curr_platforms, dict):
        raise ValueError("toolchain policy platforms malformed")
    if set(prev_platforms) != set(curr_platforms):
        raise ValueError("toolchain policy platform set changed")
    for platform in prev_platforms:
        if platform != WINDOWS_PLATFORM and prev_platforms[platform] != curr_platforms[platform]:
            raise ValueError(f"toolchain policy transition changes {platform}")
    before = _policy_windows(previous)
    after = _policy_windows(current)
    if set(before) != set(after):
        raise ValueError("Windows policy carrier fields changed")
    changed = {key for key in before if before.get(key) != after.get(key)}
    if not changed or not changed <= ALLOWED_WINDOWS_DIFF:
        raise ValueError("Windows transition is not bounded to imageVersion/git")
    if changed != set(expected_changes):
        raise ValueError(f"declared Windows transition differs: expected {sorted(expected_changes)}, observed {sorted(changed)}")


def validate_registry(root: Path, registry_path: Path) -> dict[str, Any]:
    registry = strict_object(registry_path, "runner succession registry")
    if registry.get("standard") != "EIGIIB-P1-A9-F1-RUNNER-DISTRIBUTION-SUCCESSION-1.0":
        raise ValueError("unexpected runner succession standard")
    if registry.get("platform") != WINDOWS_PLATFORM:
        raise ValueError("runner succession platform must be windows-2025")
    if registry.get("selectionPolicy") != "exact-image-version-and-git-version":
        raise ValueError("runner succession selection policy is not exact")
    generations = registry.get("generations")
    if not isinstance(generations, list) or not generations:
        raise ValueError("runner succession generations must be a non-empty array")
    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    previous_policy: dict[str, Any] | None = None
    previous_id: str | None = None
    policies: list[tuple[dict[str, Any], Path]] = []
    for index, entry in enumerate(generations):
        if not isinstance(entry, dict):
            raise ValueError("runner generation must be an object")
        if entry.get("generation") != index:
            raise ValueError("runner generations must be contiguous and ordered")
        generation_id = entry.get("id")
        if not isinstance(generation_id, str) or not generation_id or generation_id in seen_ids:
            raise ValueError("runner generation id is invalid or duplicated")
        seen_ids.add(generation_id)
        expected_predecessor = None if index == 0 else previous_id
        if entry.get("predecessor") != expected_predecessor:
            raise ValueError("runner generation predecessor is not exact")
        policy_rel = entry.get("policyPath")
        if not isinstance(policy_rel, str) or not policy_rel:
            raise ValueError("runner generation policyPath missing")
        policy_path = (root / policy_rel).resolve()
        try:
            policy_path.relative_to(root.resolve())
        except ValueError as exc:
            raise ValueError("runner generation policyPath escapes repository") from exc
        if not policy_path.is_file() or policy_path.is_symlink():
            raise ValueError(f"runner generation policy unavailable: {policy_rel}")
        policy = strict_object(policy_path, f"runner generation {generation_id} policy")
        windows = _policy_windows(policy)
        pair = (entry.get("imageVersion"), entry.get("git"))
        if not all(isinstance(x, str) and x for x in pair):
            raise ValueError("runner generation exact pair missing")
        if pair != (windows.get("imageVersion"), windows.get("git")):
            raise ValueError("runner generation pair does not match policy")
        if pair in seen_pairs:
            raise ValueError("runner distribution pair duplicated")
        seen_pairs.add(pair)
        declared = entry.get("changedFromPredecessor")
        if not isinstance(declared, list) or any(x not in ALLOWED_WINDOWS_DIFF for x in declared):
            raise ValueError("changedFromPredecessor is malformed")
        if index == 0:
            if declared:
                raise ValueError("generation zero cannot declare predecessor changes")
        else:
            assert previous_policy is not None
            _validate_policy_transition(previous_policy, policy, declared)
        policies.append((entry, policy_path))
        previous_policy = policy
        previous_id = generation_id
    return {"registry": registry, "policies": policies}


def select_policy(root: Path, registry_path: Path, platform: str, image_version: str, git_version: str) -> Path:
    validated = validate_registry(root, registry_path)
    registry = validated["registry"]
    if platform != WINDOWS_PLATFORM:
        rel = registry.get("nonWindowsPolicyPath")
        if not isinstance(rel, str) or not rel:
            raise ValueError("nonWindowsPolicyPath missing")
        path = (root / rel).resolve()
        if not path.is_file() or path.is_symlink():
            raise ValueError("non-Windows policy unavailable")
        return path
    for entry, path in validated["policies"]:
        if entry["imageVersion"] == image_version and entry["git"] == git_version:
            return path
    raise ValueError(f"unregistered Windows distribution: {image_version}|{git_version}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--platform", default=WINDOWS_PLATFORM)
    parser.add_argument("--image-version", default="")
    parser.add_argument("--git-version", default="")
    parser.add_argument("--select-policy", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    registry = args.registry.resolve()
    try:
        validated = validate_registry(root, registry)
        selected: Path | None = None
        if args.select_policy:
            selected = select_policy(root, registry, args.platform, args.image_version, args.git_version)
        result = {
            "standard": "EIGIIB-P1-A9-F1-RUNNER-DISTRIBUTION-SUCCESSION-1.0",
            "generationCount": len(validated["policies"]),
            "result": "conformant",
        }
        if selected is not None:
            if args.json:
                result["selectedPolicy"] = selected.relative_to(root).as_posix()
            else:
                print(selected.relative_to(root).as_posix())
                return 0
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"P1A9F1.RUNNER.SUCCESSION.FAILURE: {exc}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
