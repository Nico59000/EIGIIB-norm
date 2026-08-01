from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from eigiib_p1_a7_authority_common import (  # noqa: E402
    authority_root,
    canonical_json_bytes,
    content_root,
    git_blob_sha1,
    strict_json_bytes,
)
from eigiib_p1_a7_authority_inventory import build_report  # noqa: E402


class AuthorityFreezeTests(unittest.TestCase):
    def test_git_blob_identity_matches_known_fixture(self) -> None:
        self.assertEqual(git_blob_sha1(b"test\n"), "9daeafb9864cf43055ae93beb0afd6c7d144bfa4")

    def test_authority_root_is_order_independent(self) -> None:
        rows = [
            {"path": "z.json", "gitBlobSha1": "1" * 40},
            {"path": "a.json", "gitBlobSha1": "2" * 40},
        ]
        self.assertEqual(authority_root(rows), authority_root(list(reversed(rows))))

    def test_content_root_changes_with_bytes(self) -> None:
        first = [{"path": "a", "bytes": 1, "sha256": "0" * 64}]
        second = [{"path": "a", "bytes": 2, "sha256": "0" * 64}]
        self.assertNotEqual(content_root(first), content_root(second))

    def test_strict_json_rejects_duplicate_member(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
            strict_json_bytes(b'{"a":1,"a":2}', "test")

    def test_repository_authority_root_is_frozen(self) -> None:
        manifest_path = Path(__file__).resolve().parents[1] / "tests/fixtures/p1-a7/a7.7-authority-freeze.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            authority_root(manifest["entries"]),
            "e338247156165c48b7b1ce88a69f24123defc0162b1f3f6a58c4ecd510e105be",
        )

    def test_canonical_report_matches_registered_result(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "tests/fixtures/p1-a7/a7.7-authority-freeze.json").read_text(encoding="utf-8"))
        expected = json.loads((root / "tests/fixtures/p1-a7/expected-a7.7-authority-report.json").read_text(encoding="utf-8"))
        self.assertEqual(canonical_json_bytes(build_report(manifest)), canonical_json_bytes(expected))


if __name__ == "__main__":
    unittest.main()
