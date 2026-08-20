"""
test_version.py -- reeflex_mcp.__version__ must match pyproject.toml.

Guards against the single-source-of-truth regression (RFX-7): __version__
used to be hardcoded and silently drifted from the installed/published
version. This test fails the moment the two diverge again.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import reeflex_mcp

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


class TestVersionMatchesPyproject(unittest.TestCase):
    def test_version_matches_pyproject(self):
        data = tomllib.loads(_PYPROJECT.read_text())
        expected = data["project"]["version"]
        self.assertEqual(reeflex_mcp.__version__, expected)


if __name__ == "__main__":
    unittest.main()
