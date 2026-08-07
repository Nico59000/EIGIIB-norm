from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a9_f1_runner_succession import (  # noqa: E402
    _validate_policy_transition,
    select_policy,
    strict_object,
    validate_registry,
)

REGISTRY = ROOT / "tests/fixtures/p1-a9/a7.7-toolchain-policy-succession.json"


class P1A9F1RunnerSuccessionTests(unittest.TestCase):
    def test_registry_is_append_only_and_contiguous(self) -> None:
        result = validate_registry(ROOT, REGISTRY)
        self.assertEqual(len(result["policies"]), 3)
        self.assertEqual([x[0]["generation"] for x in result["policies"]], [0, 1, 2])

    def test_current_windows_distribution_selects_generation_two(self) -> None:
        selected = select_policy(
            ROOT,
            REGISTRY,
            "windows-2025",
            "20260803.193.1",
            "git version 2.55.0.windows.3",
        )
        self.assertEqual(
            selected.relative_to(ROOT).as_posix(),
            "tests/fixtures/p1-a9/a7.7-toolchain-policy-revision-2.json",
        )

    def test_unknown_windows_distribution_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unregistered Windows distribution"):
            select_policy(ROOT, REGISTRY, "windows-2025", "20990101.1", "git version 99")

    def test_generation_two_only_changes_image_version(self) -> None:
        previous = strict_object(
            ROOT / "tests/fixtures/p1-a9/a7.7-toolchain-policy-revision.json", "g1"
        )
        current = strict_object(
            ROOT / "tests/fixtures/p1-a9/a7.7-toolchain-policy-revision-2.json", "g2"
        )
        _validate_policy_transition(previous, current, ["imageVersion"])
        mutated = copy.deepcopy(current)
        mutated["platforms"]["windows-2025"]["openssl"] = "OpenSSL unexpected"
        with self.assertRaises(ValueError):
            _validate_policy_transition(previous, mutated, ["imageVersion"])


if __name__ == "__main__":
    unittest.main()
