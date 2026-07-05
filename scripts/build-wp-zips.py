#!/usr/bin/env python3
"""Build the Reeflex WordPress plugin zips + the verify / test-abilities zips.

The GitHub Actions runner is not guaranteed to have the `zip` binary, so we use
Python's stdlib `zipfile`. This script is the SINGLE SOURCE OF TRUTH for how the
zip release artifacts are packaged: the release workflow
(`.github/workflows/release.yml`) calls it, and a maintainer can run it locally
for the manual-fallback path (see `docs/RELEASING.md`).

Outputs (written into --out, default ./dist-artifacts):

  reeflex-gate-wordpress-standard.zip
      Standard plugin form. Everything lives under a top-level `reeflex-gate/`
      folder so it unzips straight into wp-content/plugins/reeflex-gate/.
      14 files as of release 0.1.6.

  reeflex-gate-wordpress-mu.zip
      Must-Use plugin form. The loader `reeflex-gate.php` sits at the ZIP ROOT
      (mu-plugins auto-loads top-level .php files only) and its companion classes
      live in a `reeflex-gate/` subfolder. No readme/license/uninstall.
      11 files as of release 0.1.6.

  reeflex-verify.zip
      The conformance / verify CLI (reeflex-verify.py + its README).

  reeflex-test-abilities.zip
      The tiny WordPress plugin that registers synthetic abilities used to
      exercise the adapter end-to-end.

The `class-*.php` list is GLOBBED, so adding a class under
`reeflex-wordpress/reeflex-gate/` automatically grows both gate zips. HIL Phase 2
added two classes (holds-store + normalizer split), taking the counts from
12 standard / 9 mu to 14 standard / 11 mu. A future maintainer who adds/removes
a class should expect these counts to move and update docs/RELEASING.md.

The archives are written deterministically (fixed member order + fixed mtime), so
re-running on unchanged sources yields byte-identical zips (stable SHA256).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

# Fixed timestamp for every member -> reproducible archives across runs/machines.
# (zip epoch minimum is 1980-01-01.)
FIXED_DATE = (1980, 1, 1, 0, 0, 0)


def _repo_root() -> Path:
    # This script lives in <repo>/scripts/, so the repo root is its parent's parent.
    return Path(__file__).resolve().parent.parent


def _require(path: Path) -> Path:
    if not path.is_file():
        sys.exit(f"ERROR: expected source file is missing: {path}")
    return path


def _add(zf: zipfile.ZipFile, arcname: str, src: Path) -> None:
    """Add src to the archive under arcname with a fixed mtime + perms."""
    data = _require(src).read_bytes()
    info = zipfile.ZipInfo(arcname, date_time=FIXED_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o644 & 0xFFFF) << 16  # -rw-r--r--
    zf.writestr(info, data)


def _class_files(gate_dir: Path) -> list[Path]:
    classes = sorted(gate_dir.glob("class-*.php"))
    if not classes:
        sys.exit(f"ERROR: no class-*.php found under {gate_dir}")
    return classes


def build_standard(root: Path, out: Path) -> Path:
    """Standard plugin: everything under a top-level reeflex-gate/ folder."""
    wp = root / "reeflex-wordpress"
    gate = wp / "reeflex-gate"
    target = out / "reeflex-gate-wordpress-standard.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        _add(zf, "reeflex-gate/reeflex-gate.php", wp / "reeflex-gate.php")
        for cls in _class_files(gate):
            _add(zf, f"reeflex-gate/{cls.name}", cls)
        _add(zf, "reeflex-gate/index.php", gate / "index.php")
        _add(zf, "reeflex-gate/languages/index.php", gate / "languages" / "index.php")
        _add(zf, "reeflex-gate/uninstall.php", wp / "uninstall.php")
        _add(zf, "reeflex-gate/readme.txt", wp / "readme.txt")
        _add(zf, "reeflex-gate/license.txt", wp / "license.txt")
    return target


def build_mu(root: Path, out: Path) -> Path:
    """Must-Use plugin: loader at ZIP ROOT, classes in a reeflex-gate/ subfolder."""
    wp = root / "reeflex-wordpress"
    gate = wp / "reeflex-gate"
    target = out / "reeflex-gate-wordpress-mu.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        _add(zf, "reeflex-gate.php", wp / "reeflex-gate.php")
        for cls in _class_files(gate):
            _add(zf, f"reeflex-gate/{cls.name}", cls)
        _add(zf, "reeflex-gate/index.php", gate / "index.php")
        _add(zf, "reeflex-gate/languages/index.php", gate / "languages" / "index.php")
    return target


def build_verify(root: Path, out: Path) -> Path:
    """The conformance / verify CLI."""
    verify = root / "reeflex-verify"
    target = out / "reeflex-verify.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        _add(zf, "reeflex-verify/reeflex-verify.py", verify / "reeflex-verify.py")
        _add(zf, "reeflex-verify/README.md", verify / "README.md")
    return target


def build_test_abilities(root: Path, out: Path) -> Path:
    """The WordPress test-abilities plugin used to exercise the adapter."""
    src = (
        root
        / "reeflex-verify"
        / "wordpress-test-plugin"
        / "reeflex-test-abilities"
        / "reeflex-test-abilities.php"
    )
    target = out / "reeflex-test-abilities.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        _add(zf, "reeflex-test-abilities/reeflex-test-abilities.php", src)
    return target


def _summary(target: Path) -> str:
    with zipfile.ZipFile(target) as zf:
        members = [n for n in zf.namelist() if not n.endswith("/")]
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return f"{target.name:38s} {len(members):3d} files  sha256={digest}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default="dist-artifacts",
        help="output directory for the zips (created if absent)",
    )
    parser.add_argument(
        "--root",
        default=str(_repo_root()),
        help="repository root (defaults to the parent of this script's dir)",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    built = [
        build_standard(root, out),
        build_mu(root, out),
        build_verify(root, out),
        build_test_abilities(root, out),
    ]

    print(f"Built {len(built)} zip artifact(s) into {out}:")
    for target in built:
        print("  " + _summary(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
