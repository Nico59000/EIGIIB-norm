"""Platform toolchain attestation for P1-A7.7."""
from __future__ import annotations

import hashlib
import os
import platform as py_platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a7_authority_common import PLATFORMS

ACTION_PINS = {
    "checkout": "d23441a48e516b6c34aea4fa41551a30e30af803",
    "setupPython": "ece7cb06caefa5fff74198d8649806c4678c61a1",
    "setupGo": "924ae3a1cded613372ab5595356fb5720e22ba16",
}


def run_text(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def executable_attestation(name: str) -> dict[str, Any]:
    path_text = sys.executable if name == "python" else shutil.which(name)
    if not path_text:
        raise ValueError(f"required executable unavailable: {name}")
    path = Path(path_text).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def validate_toolchain(root: Path, policy: dict[str, Any], platform_name: str) -> tuple[dict[str, str], dict[str, Any]]:
    if platform_name not in PLATFORMS:
        raise ValueError(f"unsupported platform label: {platform_name}")
    expected_fields = {
        "standard", "actions", "common", "platforms",
        "binaryIdentityPolicy", "semanticEqualityPolicy",
    }
    if set(policy) != expected_fields or policy.get("standard") != "EIGIIB-P1-A7.7-TOOLCHAIN-1.0":
        raise ValueError("toolchain policy fields or standard differ")
    if policy.get("actions") != ACTION_PINS:
        raise ValueError("pinned action identities differ")
    if policy.get("binaryIdentityPolicy") != "platform-specific-sha256-attestation":
        raise ValueError("binary identity policy differs")
    if policy.get("semanticEqualityPolicy") != "byte-identical-canonical-authority-report":
        raise ValueError("semantic equality policy differs")
    common = policy.get("common")
    platforms = policy.get("platforms")
    if not isinstance(common, dict) or not isinstance(platforms, dict) or set(platforms) != set(PLATFORMS):
        raise ValueError("toolchain policy carrier differs")
    expected = platforms[platform_name]
    versions = {
        "python": py_platform.python_version(),
        "go": run_text(["go", "version"], root).split()[2],
        "openssl": run_text(["openssl", "version"], root).split(" (Library:", 1)[0],
        "git": run_text(["git", "--version"], root),
    }
    if versions["python"] != common.get("python") or versions["go"] != common.get("go"):
        raise ValueError(f"common toolchain version differs: {versions!r}")
    if versions["openssl"] != expected.get("openssl") or versions["git"] != expected.get("git"):
        raise ValueError(f"platform toolchain version differs: {versions!r}")
    runner_os = os.environ.get("RUNNER_OS", "")
    runner_arch = os.environ.get("RUNNER_ARCH", "")
    image_version = os.environ.get("ImageVersion", "")
    if runner_os != expected.get("runnerOS") or runner_arch != expected.get("runnerArch"):
        raise ValueError("runner OS or architecture differs")
    if image_version != expected.get("imageVersion"):
        raise ValueError(f"runner image version differs: {image_version!r}")
    return versions, {
        "runner": {
            "os": runner_os,
            "arch": runner_arch,
            "image_os": os.environ.get("ImageOS", expected.get("image", "")),
            "image_version": image_version,
        },
        "executables": {name: executable_attestation(name) for name in ("python", "go", "openssl", "git")},
    }
