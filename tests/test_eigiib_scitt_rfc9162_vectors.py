import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import eigiib_scitt_receipt as m


class P1A3RFC9162Vectors(unittest.TestCase):
    def test_two_leaf_left_and_right_paths(self):
        e0, e1 = b"entry-0", b"entry-1"
        h0, h1 = m.leaf_hash(e0), m.leaf_hash(e1)
        root = m.node_hash(h0, h1)
        self.assertEqual(m.inclusion_root(e0, 2, 0, [h1]), root)
        self.assertEqual(m.inclusion_root(e1, 2, 1, [h0]), root)

    def test_three_leaf_rightmost_path(self):
        e0, e1, e2 = b"entry-0", b"entry-1", b"entry-2"
        left = m.node_hash(m.leaf_hash(e0), m.leaf_hash(e1))
        root = m.node_hash(left, m.leaf_hash(e2))
        self.assertEqual(m.inclusion_root(e2, 3, 2, [left]), root)

    def test_three_leaf_leftmost_path(self):
        e0, e1, e2 = b"entry-0", b"entry-1", b"entry-2"
        h0, h1, h2 = m.leaf_hash(e0), m.leaf_hash(e1), m.leaf_hash(e2)
        root = m.node_hash(m.node_hash(h0, h1), h2)
        self.assertEqual(m.inclusion_root(e0, 3, 0, [h1, h2]), root)

    def test_incomplete_path_rejected(self):
        e0, e1 = b"entry-0", b"entry-1"
        with self.assertRaises(ValueError):
            m.inclusion_root(e0, 2, 0, [])

    def test_extra_path_rejected(self):
        e0, e1 = b"entry-0", b"entry-1"
        h1 = m.leaf_hash(e1)
        with self.assertRaises(ValueError):
            m.inclusion_root(e0, 2, 0, [h1, h1])


if __name__ == "__main__":
    unittest.main()
