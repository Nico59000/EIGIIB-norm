from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from eigiib_p1_a20_common import FIXTURE, build_report, load_json, validate_bundle


class P1A20RunnerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_json(FIXTURE / "runner-admission-bundle.json")
        cls.expected = load_json(FIXTURE / "expected-report.json")

    def test_001_exact_report(self) -> None:
        self.assertEqual(build_report(copy.deepcopy(self.bundle)), self.expected)

    def test_002_six_routes_replay(self) -> None:
        self.assertEqual(len(validate_bundle(copy.deepcopy(self.bundle))), 6)

    def test_003_three_registered_runners(self) -> None:
        self.assertEqual(len(self.bundle["registry"]["runners"]), 3)

    def test_004_current_epoch_inside_window(self) -> None:
        succession = self.bundle["registry"]["succession"][0]
        self.assertLessEqual(self.bundle["registry"]["currentEpoch"], succession["compatibilityEndsEpoch"])


def _mutations(bundle: dict) -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []

    def add(name: str, value: dict) -> None:
        cases.append((name, value))

    mutated = copy.deepcopy(bundle)
    mutated["unexpected"] = True
    add("bundle-extra-field", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["sequence"] = 2
    add("registry-sequence", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["runners"][1]["runnerId"] = mutated["registry"]["runners"][0]["runnerId"]
    add("duplicate-runner", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["runners"][0]["status"] = "suspended"
    add("inactive-runner", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["runners"][0]["admissionEpoch"] = 9
    add("future-admission", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["runners"][0]["admittedToolchains"] = ["python-3.13", "openssl-3", "go-1.26"]
    add("noncanonical-toolchain-set", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["runners"][0]["admittedToolchains"][0] = "unknown"
    add("unknown-runner-toolchain", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["toolchains"][1]["predecessor"] = "unknown"
    add("unknown-predecessor", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["toolchains"][1]["compatibilityWindow"] = {"min":"1.26.5","max":"1.25.0"}
    add("reversed-version-window", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["succession"][0]["effectiveEpoch"] = 5
    add("reversed-epoch-window", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["succession"][0]["rollbackAllowedUntilEpoch"] = 5
    add("rollback-beyond-window", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["runnerId"] = "unknown"
    add("route-decision-mismatch-unregistered", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["requestedToolchains"].pop("openssl-3")
    add("toolchain-set-not-admitted", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["requestedToolchains"]["python-3.13"] = "3.13.13"
    add("version-outside-window", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][3]["rollback"]["target"] = "python-3.13"
    add("unauthorized-rollback-target", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][3]["rollback"]["epoch"] = 5
    add("expired-rollback-route", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["registry"]["currentEpoch"] = 5
    add("expired-compatibility-window", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][1]["routeId"] = mutated["routes"][0]["routeId"]
    add("duplicate-route-id", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["decision"] = "reject"
    add("decision-tamper", mutated)

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["reason"] = "runner-not-registered"
    add("reason-tamper", mutated)

    return cases


def _make_rejection(index: int, name: str):
    def test(self: P1A20RunnerAdmissionTests) -> None:
        mutated = _mutations(self.bundle)[index][1]
        with self.assertRaises((ValueError, KeyError), msg=name):
            validate_bundle(mutated)
    return test


for index, (name, _) in enumerate(_mutations(load_json(FIXTURE / "runner-admission-bundle.json"))):
    setattr(P1A20RunnerAdmissionTests, f"test_{index + 5:03d}_reject_{name.replace('-', '_')}", _make_rejection(index, name))


if __name__ == "__main__":
    unittest.main()
