"""Unit tests for scripts/check_diagram_contrast.py (RFX-268).

The one property everything else rests on, same as the dependency-floor
checker: THE CHECKER MUST FAIL ON THE TREE AS IT WAS BEFORE THE FIX. A
contrast check that has never been observed to refuse anything is not evidence
about the diagrams — and this particular defect shipped for two weeks under a
green `--strict`, so a green `--strict` is exactly what is not trusted here.

Written as unittest TestCases because `gate.py` runs this root with
`unittest discover -s scripts/tests -t scripts`; bare pytest functions here
would collect zero tests and pass forever (RFX-87).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_diagram_contrast as cdc  # noqa: E402


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCS = os.path.join(REPO_ROOT, "docs")

# extra.css as it stood at 2148514 — the mechanism absent, the ink under its
# old name. Trimmed to the two declarations the checker reads.
CSS_PRE_FIX = """
[data-md-color-scheme="default"] {
  --md-mermaid-node-bg-color: #fbeee7;
  --md-mermaid-label-fg-color: #263041;
}
[data-md-color-scheme="slate"] {
  --md-mermaid-node-bg-color: #202a46;
  --md-mermaid-label-fg-color: #dfe6f5;
}
.md-typeset .mermaid { text-align: center; margin: 1.6rem 0; }
"""

CSS_FIXED = """
[data-md-color-scheme="default"] {
  --md-mermaid-node-bg-color: #fbeee7;
  --rfx-mermaid-ink: #263041;
  --md-mermaid-label-fg-color: var(--rfx-mermaid-ink);
}
[data-md-color-scheme="slate"] {
  --md-mermaid-node-bg-color: #202a46;
  --rfx-mermaid-ink: #dfe6f5;
  --md-mermaid-label-fg-color: var(--rfx-mermaid-ink);
}
.md-typeset .mermaid {
  text-align: center;
  color: var(--rfx-mermaid-ink);
  --md-mermaid-label-fg-color: currentColor;
}
"""

MD_OK = """# page

```mermaid
flowchart TD
    A["one"] --> B["two"]
    classDef deny fill:#7f1d1d,stroke:#ef4444,color:#fff;
    class B deny;
```
"""

# The "fixes five classDefs and leaves the sixth" case: a coloured fill with no
# `color:`, so the node falls back to the palette ink.
MD_UNCOLOURED_INK_ON_DARK_FILL = """# page

```mermaid
flowchart TD
    A["one"] --> B["two"]
    classDef deny fill:#7f1d1d,stroke:#ef4444;
    class B deny;
```
"""


def _tree(tmp, css, md=None):
    os.makedirs(os.path.join(tmp, "stylesheets"))
    with open(os.path.join(tmp, "stylesheets", "extra.css"), "w") as fh:
        fh.write(css)
    if md is not None:
        with open(os.path.join(tmp, "page.md"), "w") as fh:
            fh.write(md)
    return tmp


class ColourMathTests(unittest.TestCase):
    def test_parse_hex_short_and_long(self):
        self.assertEqual(cdc.parse_hex("#fff"), (255, 255, 255))
        self.assertEqual(cdc.parse_hex("#7f1d1d"), (127, 29, 29))

    def test_parse_hex_refuses_what_it_cannot_read(self):
        # `var(--x)` is the value that looks reasonable and is not: mermaid
        # 11.6.0's classDef lexer rejects it and the diagram does not render.
        for bad in ("var(--rfx-diag-deny-fill)", "red", "rgb(1,2,3)", "", "#12"):
            self.assertIsNone(cdc.parse_hex(bad), bad)

    def test_contrast_reproduces_the_measured_numbers(self):
        # These are the pixel readings from the fixed build, both palettes.
        self.assertAlmostEqual(
            cdc.contrast_ratio((255, 255, 255), (127, 29, 29)), 10.02, places=2)
        self.assertAlmostEqual(
            cdc.contrast_ratio((255, 255, 255), (76, 29, 149)), 10.95, places=2)
        # ...and the defect as it shipped: #263041 on the deny fill.
        self.assertAlmostEqual(
            cdc.contrast_ratio((38, 48, 65), (127, 29, 29)), 1.33, places=2)

    def test_contrast_is_symmetric(self):
        self.assertEqual(cdc.contrast_ratio((255, 255, 255), (20, 83, 45)),
                         cdc.contrast_ratio((20, 83, 45), (255, 255, 255)))


class MechanismTests(unittest.TestCase):
    def test_absent_in_the_stylesheet_as_it_shipped(self):
        self.assertFalse(cdc.mechanism_present(CSS_PRE_FIX))

    def test_present_after_the_fix(self):
        self.assertTrue(cdc.mechanism_present(CSS_FIXED))

    def test_a_currentcolor_somewhere_else_does_not_count(self):
        # extra.css already says `-webkit-text-fill-color: currentColor` in the
        # hero block; that must not read as the mermaid mechanism.
        self.assertFalse(cdc.mechanism_present(
            ".reeflex-hero h1 { -webkit-text-fill-color: currentColor; }"))

    def test_the_declaration_must_be_on_a_mermaid_rule(self):
        self.assertFalse(cdc.mechanism_present(
            ":root { --md-mermaid-label-fg-color: currentColor; }"))


class ClassDefParsingTests(unittest.TestCase):
    def test_reads_ids_and_declarations(self):
        found = list(cdc.iter_classdefs(MD_OK))
        self.assertEqual(len(found), 1)
        _line, ids, props = found[0]
        self.assertEqual(ids, ["deny"])
        self.assertEqual(props["fill"], "#7f1d1d")
        self.assertEqual(props["color"], "#fff")

    def test_comma_separated_ids(self):
        src = "```mermaid\nflowchart TD\n classDef a,b fill:#fff,color:#000;\n```\n"
        _line, ids, _props = list(cdc.iter_classdefs(src))[0]
        self.assertEqual(ids, ["a", "b"])

    def test_ignores_classdef_like_text_outside_a_mermaid_fence(self):
        src = "prose\n\n```python\nclassDef deny fill:#7f1d1d;\n```\n"
        self.assertEqual(list(cdc.iter_classdefs(src)), [])


class EndToEndTests(unittest.TestCase):
    def test_clean_tree_has_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(cdc.check(_tree(tmp, CSS_FIXED, MD_OK)), [])

    def test_the_tree_as_it_shipped_is_refused(self):
        # THE control. Same markdown, pre-fix stylesheet: the classDefs all say
        # `color:#fff` and the page painted #263041, so the only thing that can
        # catch it is the mechanism assertion. It must fire.
        with tempfile.TemporaryDirectory() as tmp:
            findings = cdc.check(_tree(tmp, CSS_PRE_FIX, MD_OK))
            self.assertTrue(findings)
            self.assertTrue(any("mechanism is GONE" in f for f in findings),
                            findings)

    def test_a_classdef_with_no_colour_of_its_own_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = cdc.check(
                _tree(tmp, CSS_FIXED, MD_UNCOLOURED_INK_ON_DARK_FILL))
            self.assertTrue(any("1.33:1" in f and "'default'" in f
                                for f in findings), findings)

    def test_a_colour_it_cannot_read_is_reported_not_skipped(self):
        md = MD_OK.replace("fill:#7f1d1d", "fill:var(--x)")
        with tempfile.TemporaryDirectory() as tmp:
            findings = cdc.check(_tree(tmp, CSS_FIXED, md))
            self.assertTrue(any("not a 3- or 6-digit hex" in f
                                for f in findings), findings)

    def test_a_missing_stylesheet_is_a_finding_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = cdc.check(tmp)
            self.assertTrue(any("cannot read" in f for f in findings), findings)

    def test_the_real_docs_tree_passes(self):
        self.assertEqual(cdc.check(DOCS), [])


if __name__ == "__main__":
    unittest.main()
