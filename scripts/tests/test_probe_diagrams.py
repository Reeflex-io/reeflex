"""Tests for scripts/probe_diagrams.py — the parts that do not need a browser.

The browser-side checks (render / palette / webfont / contrast / ink-identity /
label-size) are proved the only way they can be: by injecting a real defect into
the shipped tree, rebuilding the site and watching the probe go red. Those
transcripts are in the round's evidence directory; what is tested here is the
logic that decides a verdict once the pixels are in.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import probe_diagrams as pd  # noqa: E402


def finding(check="label-size", src="docs/a.md", palette="default",
            diagram="D", value=5.0, label="x"):
    return {"check": check, "severity": "FAIL", "src": src, "palette": palette,
            "diagram": diagram, "label": label, "value": value, "message": "m"}


def baseline(entries):
    return {"%s|%s|%s|%s" % (e["check"], e["src"], e["palette"], e["diagram"]): e
            for e in entries}


ENTRY = {"check": "label-size", "src": "docs/a.md", "palette": "default",
         "diagram": "D", "labels": 2, "worst": 5.0, "ticket": "RFX-1",
         "note": "n"}


class TestBaselineRatchet(unittest.TestCase):
    def test_a_known_finding_is_downgraded_and_keeps_its_ticket(self):
        out = pd.apply_baseline([finding(), finding(label="y")],
                                baseline([ENTRY]), "b.json")
        self.assertEqual([f["severity"] for f in out], ["KNOWN"])
        self.assertIn("RFX-1", out[0]["message"])

    def test_an_unlisted_finding_still_fails(self):
        out = pd.apply_baseline([finding(diagram="OTHER")],
                                baseline([ENTRY]), "b.json")
        by_check = {f["check"]: f for f in out}
        self.assertEqual(by_check["label-size"]["severity"], "FAIL")
        self.assertEqual(by_check["label-size"]["diagram"], "OTHER")
        # The listed entry matched nothing this run, so it is stale as well.
        self.assertEqual(by_check["baseline-stale"]["severity"], "FAIL")

    def test_a_known_defect_that_deepens_fails(self):
        # 5.0 baselined, 5% slack -> 4.75 is the floor.
        out = pd.apply_baseline([finding(value=4.70)], baseline([ENTRY]), "b.json")
        self.assertEqual([f["severity"] for f in out], ["FAIL"])
        self.assertIn("got WORSE", out[0]["message"])

    def test_the_slack_covers_the_font_regime_difference(self):
        # The webfont-vs-fallback spread measured on this site is up to 3.2%.
        out = pd.apply_baseline([finding(value=5.0 * 0.968)],
                                baseline([ENTRY]), "b.json")
        self.assertEqual([f["severity"] for f in out], ["KNOWN"])

    def test_a_known_defect_that_spreads_to_more_labels_fails(self):
        out = pd.apply_baseline(
            [finding(label=c) for c in "abc"], baseline([ENTRY]), "b.json")
        self.assertEqual([f["severity"] for f in out], ["FAIL"])
        self.assertIn("SPREAD", out[0]["message"])

    def test_a_baseline_entry_with_no_finding_fails_as_stale(self):
        """The file is a worklist: a fixed defect may not stay listed."""
        out = pd.apply_baseline([], baseline([ENTRY]), "b.json")
        self.assertEqual([f["check"] for f in out], ["baseline-stale"])
        self.assertEqual(out[0]["severity"], "FAIL")
        self.assertIn("may only shrink", out[0]["message"])

    def test_the_baseline_cannot_excuse_a_mechanism_failure(self):
        """render / palette / webfont / ink-identity are not baselineable, so an
        entry naming one of them does not stop the finding failing the run."""
        entry = dict(ENTRY, check="ink-identity")
        out = pd.apply_baseline([finding(check="ink-identity", value=None)],
                                baseline([entry]), "b.json")
        sev = {f["check"]: f["severity"] for f in out}
        self.assertEqual(sev["ink-identity"], "FAIL")
        # ...and the unusable entry is itself reported as stale.
        self.assertEqual(sev["baseline-stale"], "FAIL")

    def test_no_baseline_file_leaves_every_finding_failing(self):
        out = pd.apply_baseline([finding()], {}, "(none)")
        self.assertEqual([f["severity"] for f in out], ["FAIL"])


class TestShippedBaselineFile(unittest.TestCase):
    """The file that actually ships has to stay loadable and ticketed."""

    def setUp(self):
        self.path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "diagram_probe_baseline.json")

    def test_it_parses_and_every_entry_names_a_ticket(self):
        with open(self.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertTrue(doc["known"], "an empty worklist should be deleted, not shipped")
        for e in doc["known"]:
            for field in ("check", "src", "palette", "diagram", "labels",
                          "worst", "ticket", "note"):
                self.assertIn(field, e, "%s missing %s" % (e.get("diagram"), field))
            self.assertRegex(e["ticket"], r"^RFX-\d+$")
            self.assertIn(e["check"], pd.BASELINEABLE,
                          "%s is not a baselineable check" % e["check"])

    def test_loading_it_produces_unique_keys(self):
        loaded = pd.load_baseline(self.path)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(len(loaded), len(json.load(fh)["known"]),
                             "two entries collide on (check, src, palette, diagram)")


class TestSourceReading(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "stylesheets"))
        os.makedirs(os.path.join(self.dir, "sub"))

    def _write(self, rel, text):
        path = os.path.join(self.dir, rel)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_only_pages_with_a_mermaid_fence_are_probed(self):
        self._write("has.md", "# t\n\n```mermaid\nflowchart LR\nA-->B\n```\n")
        self._write("hasnt.md", "# t\n\njust prose\n")
        self._write("sub/index.md", "# t\n\n```mermaid\nflowchart LR\nA-->B\n```\n")
        urls = [u for u, _src in pd.discover_pages(self.dir)]
        self.assertIn("has", urls)
        self.assertIn("sub", urls, "a sub/index.md must map to the URL 'sub/'")
        self.assertNotIn("hasnt", urls)

    def test_a_docs_tree_with_no_diagrams_is_an_instrument_failure(self):
        """Nothing to measure is not the same as nothing wrong."""
        self._write("prose.md", "# t\n\nno diagrams here\n")
        self.assertEqual(pd.discover_pages(self.dir), [])

    def test_classdef_colours_carry_a_file_and_line(self):
        self._write("d.md", "# t\n\n```mermaid\nflowchart LR\nA-->B\n"
                            "classDef deny fill:#7f1d1d,stroke:#ef4444,color:#fff;\n```\n")
        got = pd.classdef_colours(self.dir)
        self.assertEqual(got["deny"]["color"], "#fff")
        self.assertEqual(got["deny"]["fill"], "#7f1d1d")
        self.assertEqual(got["deny"]["where"], "docs/d.md:6")

    def test_palette_and_body_inks_are_read_per_scheme(self):
        self._write("stylesheets/extra.css",
                    '[data-md-color-scheme="default"]{--rfx-mermaid-ink:#263041;'
                    '--md-default-fg-color:#33404f;}'
                    '[data-md-color-scheme="slate"]{--rfx-mermaid-ink:#dfe6f5;'
                    '--md-default-fg-color:#cbd3e6;}')
        ink = pd.css_colour_by_scheme(self.dir, pd.PALETTE_INK_VARS)
        body = pd.css_colour_by_scheme(self.dir, pd.BODY_INK_VARS)
        self.assertEqual(ink["default"], (0x26, 0x30, 0x41))
        self.assertEqual(body["slate"], (0xcb, 0xd3, 0xe6))

    def test_rfx273_is_measured_as_out_of_reach_not_assumed(self):
        """The probe declines ink-identity when the two candidate inks are too
        close to tell apart in paint. These are the shipped values, and both
        gaps sit under the floor — which is why RFX-273 stays open."""
        self._write("stylesheets/extra.css",
                    '[data-md-color-scheme="default"]{--rfx-mermaid-ink:#263041;'
                    '--md-default-fg-color:#33404f;}'
                    '[data-md-color-scheme="slate"]{--rfx-mermaid-ink:#dfe6f5;'
                    '--md-default-fg-color:#cbd3e6;}')
        ink = pd.css_colour_by_scheme(self.dir, pd.PALETTE_INK_VARS)
        body = pd.css_colour_by_scheme(self.dir, pd.BODY_INK_VARS)
        for scheme in ("default", "slate"):
            gap = pd.rgb_distance(ink[scheme], body[scheme])
            self.assertLess(gap, pd.INK_IDENTITY_MIN_GAP,
                            "%s gap %.1f" % (scheme, gap))
        # ...while a classDef #fff against either palette ink is well clear.
        self.assertGreater(pd.rgb_distance((255, 255, 255), ink["default"]),
                           pd.INK_IDENTITY_MIN_GAP)


class TestPixelSampling(unittest.TestCase):
    def _img(self, size, paint):
        from PIL import Image
        img = Image.new("RGB", size, (0, 0, 0))
        paint(img)
        return img

    def test_the_ink_is_the_colour_furthest_from_the_modal_background(self):
        from PIL import Image
        img = Image.new("RGB", (30, 30), (0x7f, 0x1d, 0x1d))   # deny fill
        for x in range(10, 20):
            for y in range(10, 20):
                img.putpixel((x, y), (255, 255, 255))           # the glyph
        got = pd.sample_ink(img, (0, 0, 30, 30), dsf=1)
        self.assertEqual(got["bg"], "#7f1d1d")
        self.assertEqual(got["ink"], "#ffffff")
        self.assertAlmostEqual(got["cr"], 10.02, places=1)

    def test_a_single_stray_pixel_does_not_become_the_ink(self):
        """Otherwise one antialiasing outlier reports a passing contrast over a
        label that is genuinely dark-on-dark."""
        from PIL import Image
        img = Image.new("RGB", (40, 40), (0x7f, 0x1d, 0x1d))
        img.putpixel((0, 0), (255, 255, 255))
        got = pd.sample_ink(img, (0, 0, 40, 40), dsf=1)
        self.assertEqual(got["ink"], "#7f1d1d")
        self.assertEqual(got["floor"], 4)   # max(3, 0.3% of 1600)

    def test_the_box_is_scaled_by_the_device_scale_factor(self):
        """The DOM hands back CSS pixels; the screenshot is device pixels. Not
        scaling reads the top-left corner of the label and calls it the label."""
        from PIL import Image
        img = Image.new("RGB", (60, 60), (0, 0, 0))
        for x in range(30, 60):
            for y in range(30, 60):
                img.putpixel((x, y), (255, 255, 255))
        # CSS box (10..20) at dsf=3 is device box (30..60): all white.
        got = pd.sample_ink(img, (10, 10, 20, 20), dsf=3)
        self.assertEqual(got["bg"], "#ffffff")
        self.assertEqual(got["px"], 900)

    def test_a_zero_area_box_returns_nothing_rather_than_a_verdict(self):
        from PIL import Image
        self.assertIsNone(pd.sample_ink(Image.new("RGB", (10, 10)),
                                        (5, 5, 5, 5), dsf=1))


class TestSharedAuthority(unittest.TestCase):
    def test_the_threshold_and_colour_maths_come_from_the_static_check(self):
        """One definition, not two: the hook and the probe must agree or the
        pair is two authorities disagreeing quietly."""
        import check_diagram_contrast as static_check
        self.assertIs(pd.MIN_CONTRAST, static_check.MIN_CONTRAST)
        self.assertIs(pd.contrast_ratio, static_check.contrast_ratio)
        self.assertIs(pd.parse_hex, static_check.parse_hex)
        self.assertIs(pd.iter_classdefs, static_check.iter_classdefs)


class TestInstrumentFailuresAreNotCleanRuns(unittest.TestCase):
    def test_a_missing_site_directory_exits_2(self):
        self.assertEqual(pd.main(["/nonexistent-site-dir-rfx266"]), 2)

    def test_a_docs_tree_with_no_diagrams_exits_2(self):
        site = tempfile.mkdtemp()
        docs = tempfile.mkdtemp()
        with open(os.path.join(docs, "p.md"), "w", encoding="utf-8") as fh:
            fh.write("# no diagrams\n")
        self.assertEqual(pd.main([site, "--docs-dir", docs]), 2)


if __name__ == "__main__":
    unittest.main()
