#!/usr/bin/env python3
"""check_diagram_contrast.py — fail the docs build when a mermaid diagram node
paints text that a reader cannot read, in EITHER palette.

WHY THIS EXISTS (RFX-268). Every coloured node on the public compliance
diagrams shipped for two weeks painting `#263041` ink on its own dark fill —
coerce 1.28:1, deny 1.33:1, allow 1.46:1, hold 1.46:1, comm 1.21:1, against
WCAG 1.4.3's 4.5:1. The DENY and HOLD boxes, with the rule ids in them, were
the least legible text on the page. Nothing caught it: `mkdocs --strict` was
green, `opa`-style linting does not exist for a picture, and two rounds of
careful measurement read the contrast at ~9:1 because they sampled
`span.nodeLabel` — the ANCESTOR that carries the intended colour — instead of
the `<p>` inside it that actually paints.

The defect arrived one classDef at a time. A round that fixes five classDefs
and leaves the sixth to the next person is how it got here, so the check below
runs over ALL of them, on every build, in both palettes.

WHAT IT CHECKS, statically, with no browser and no network:

  1. THE MECHANISM. `docs/stylesheets/extra.css` must set
     `--md-mermaid-label-fg-color: currentColor` inside a `.mermaid` rule.
     Material paints the label `<p>` with `color: var(--md-mermaid-label-fg-color)`
     from inside the shadow root, where none of our selectors reach; that
     variable set to `currentColor` is what turns the declaration into
     "inherit" and lets a classDef's `color:` reach the painting element.
     Without it, every `color:` in a classDef is decoration and the contrast
     numbers below describe a page that does not exist — so this is checked
     FIRST and reported as the cause, not as a side note.

  2. EVERY `classDef`, IN BOTH PALETTES. Effective ink is the classDef's own
     `color:` if it declares one, else the palette's `--rfx-mermaid-ink`.
     Effective fill is the classDef's own `fill:` if it declares one, else the
     palette's `--md-mermaid-node-bg-color`. Contrast must be >= 4.5:1.

  3. THE UNCOLOURED NODE, in both palettes: `--rfx-mermaid-ink` against
     `--md-mermaid-node-bg-color`.

  4. COLOURS THIS CHECKER CANNOT READ. A `fill:`/`color:` value that is not a
     3- or 6-digit hex is reported rather than skipped — an unreadable value
     means the check is blind, not that the node is fine. (`var(--x)` in
     particular is not merely unreadable here: mermaid 11.6.0's classDef lexer
     rejects it outright, measured — `Expecting 'SEMI', ... got '(-'` — and the
     whole diagram then fails to render.)

WHAT IT CANNOT SEE, and these are real gaps, not hedging:

  * It reads the markdown source, not the rendered pixels. It models what
    mermaid + Material do with a classDef; check 1 is what keeps that model
    honest, but a Material or mermaid upgrade could change the mechanism
    without changing any file this script reads. Re-measure with pixels when
    either is bumped.
  * Cluster (`subgraph`) labels, edge labels and sequence-diagram text take
    their colour from other Material variables and are not modelled here.
  * It says nothing about font size — that is the RFX-265 axis, and a legible
    colour at 5px is still not readable.

Usage as a mkdocs hook (this is how it runs in CI, via `hooks:` in mkdocs.yml):
findings are logged as WARNINGs on the `mkdocs` logger, which `mkdocs build
--strict` turns into a non-zero exit.

Standalone:  python scripts/check_diagram_contrast.py [DOCS_DIR]
             exit 0 = clean, exit 1 = at least one finding.
"""

from __future__ import annotations

import logging
import os
import re
import sys

# WCAG 2.x SC 1.4.3 (AA), normal-size text. The 3:1 "large text" allowance does
# not apply: the diagram labels measured 6-16px, far under the 18.66px bold /
# 24px threshold.
MIN_CONTRAST = 4.5

PALETTES = ("default", "slate")

log = logging.getLogger("mkdocs")

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_CLASSDEF = re.compile(r"^\s*classDef\s+(\S+)\s+(.+?);?\s*$")
_FENCE = re.compile(r"^\s*```+\s*mermaid\s*$")
_FENCE_END = re.compile(r"^\s*```+\s*$")


# --------------------------------------------------------------------------
# colour + contrast
# --------------------------------------------------------------------------
def parse_hex(value):
    """'#abc' / '#aabbcc' -> (r, g, b). None for anything else, on purpose."""
    v = value.strip()
    if not _HEX.match(v):
        return None
    v = v[1:]
    if len(v) == 3:
        v = "".join(c * 2 for c in v)
    return tuple(int(v[i:i + 2], 16) for i in (0, 2, 4))


def relative_luminance(rgb):
    def chan(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (chan(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(a, b):
    la, lb = relative_luminance(a), relative_luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


# --------------------------------------------------------------------------
# inputs
# --------------------------------------------------------------------------
def read_palette_vars(css_text):
    """{'default': {'--rfx-mermaid-ink': '#263041', ...}, 'slate': {...}}"""
    out = {}
    for scheme in PALETTES:
        # extra.css declares a scheme's variables in more than one block. Merge
        # them in source order so the LAST declaration wins, as the cascade
        # does for equal specificity — reading only the first block silently
        # reported every variable missing.
        merged = {}
        for block in re.findall(
                r'\[data-md-color-scheme="%s"\]\s*\{([^{}]*)\}' % re.escape(scheme),
                css_text, re.S):
            for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block):
                merged[k] = v.strip()
        out[scheme] = merged
    return out


def mechanism_present(css_text):
    """True when a `.mermaid` rule sets --md-mermaid-label-fg-color:currentColor.

    That single declaration is what makes a classDef `color:` reach the <p>
    that paints (see the module docstring). Without it every contrast number
    this script computes is about a page nobody is served.
    """
    for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css_text):
        if ".mermaid" not in sel:
            continue
        if re.search(r"--md-mermaid-label-fg-color\s*:\s*currentColor\s*(;|$)",
                     body, re.I):
            return True
    return False


def iter_classdefs(md_text):
    """Yield (line_no, [class ids], {prop: value}) for classDefs in mermaid fences."""
    in_fence = False
    for i, line in enumerate(md_text.splitlines(), 1):
        if not in_fence:
            if _FENCE.match(line):
                in_fence = True
            continue
        if _FENCE_END.match(line):
            in_fence = False
            continue
        m = _CLASSDEF.match(line)
        if not m:
            continue
        ids = [c.strip() for c in m.group(1).split(",") if c.strip()]
        props = {}
        for decl in m.group(2).split(","):
            if ":" not in decl:
                continue
            k, v = decl.split(":", 1)
            props[k.strip().lower()] = v.strip()
        yield i, ids, props


# --------------------------------------------------------------------------
# the check
# --------------------------------------------------------------------------
def check(docs_dir):
    """Return a list of human-readable finding strings (empty == clean)."""
    findings = []
    css_path = os.path.join(docs_dir, "stylesheets", "extra.css")
    try:
        with open(css_path, encoding="utf-8") as fh:
            css = fh.read()
    except OSError as exc:
        return ["check_diagram_contrast: cannot read %s (%s) — the palette ink "
                "is unknown, so no diagram contrast was checked at all."
                % (css_path, exc)]

    if not mechanism_present(css):
        findings.append(
            "check_diagram_contrast: RFX-268 mechanism is GONE — no `.mermaid` "
            "rule in docs/stylesheets/extra.css sets "
            "`--md-mermaid-label-fg-color: currentColor`. Without it Material "
            "paints every node label with the palette ink and a classDef's "
            "`color:` reaches nothing, whatever it says. Restore it, then "
            "re-measure with pixels in both palettes.")

    pal = read_palette_vars(css)
    ink, node_bg = {}, {}
    for scheme in PALETTES:
        # The palette ink moved from --md-mermaid-label-fg-color to
        # --rfx-mermaid-ink when the mechanism landed; read either, so this
        # check still computes real numbers against a tree that predates it
        # (which is how its own control run is done).
        for var_names, store in ((("--rfx-mermaid-ink",
                                   "--md-mermaid-label-fg-color"), ink),
                                 (("--md-mermaid-node-bg-color",), node_bg)):
            rgb, raw = None, None
            for var in var_names:
                raw = pal.get(scheme, {}).get(var)
                rgb = parse_hex(raw) if raw else None
                if rgb is not None:
                    break
            if rgb is None:
                findings.append(
                    "check_diagram_contrast: none of %s is a plain hex for the "
                    "%r palette (last read %r) — diagram contrast in that "
                    "palette was NOT checked."
                    % (", ".join(var_names), scheme, raw))
            store[scheme] = rgb

    for root, _dirs, files in os.walk(docs_dir):
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, docs_dir)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for line_no, ids, props in iter_classdefs(text):
                label = "docs/%s:%d classDef %s" % (
                    rel.replace(os.sep, "/"), line_no, ",".join(ids))
                for prop in ("fill", "color"):
                    if prop in props and parse_hex(props[prop]) is None:
                        findings.append(
                            "%s — `%s:%s` is not a 3- or 6-digit hex, so its "
                            "contrast could not be checked. (mermaid 11.6.0's "
                            "classDef lexer also rejects `var(...)`: the "
                            "diagram then fails to render entirely.)"
                            % (label, prop, props[prop]))
                for scheme in PALETTES:
                    if ink[scheme] is None or node_bg[scheme] is None:
                        continue
                    fg = parse_hex(props.get("color", "")) or ink[scheme]
                    bg = parse_hex(props.get("fill", "")) or node_bg[scheme]
                    ratio = contrast_ratio(fg, bg)
                    if ratio < MIN_CONTRAST:
                        findings.append(
                            "%s — painted ink %s on fill %s is %.2f:1 in the "
                            "%r palette, under WCAG 1.4.3's %.1f:1. %s"
                            % (label,
                               props.get("color", "(palette ink %s)" % _fmt(ink[scheme])),
                               props.get("fill", "(palette node bg %s)" % _fmt(node_bg[scheme])),
                               ratio, scheme, MIN_CONTRAST,
                               "Give the classDef a `color:` that reads on its "
                               "own fill, in BOTH palettes."))

    for scheme in PALETTES:
        if ink[scheme] is None or node_bg[scheme] is None:
            continue
        ratio = contrast_ratio(ink[scheme], node_bg[scheme])
        if ratio < MIN_CONTRAST:
            findings.append(
                "docs/stylesheets/extra.css — the UNCOLOURED node in the %r "
                "palette is %s on %s, %.2f:1, under %.1f:1."
                % (scheme, _fmt(ink[scheme]), _fmt(node_bg[scheme]),
                   ratio, MIN_CONTRAST))
    return findings


def _fmt(rgb):
    return "#%02x%02x%02x" % rgb


# --------------------------------------------------------------------------
# mkdocs hook entry point
# --------------------------------------------------------------------------
def on_post_build(config, **_kwargs):
    findings = check(config["docs_dir"])
    for f in findings:
        log.warning(f)
    return None


# --------------------------------------------------------------------------
if __name__ == "__main__":
    docs = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
    results = check(docs)
    for finding in results:
        print("FAIL: %s" % finding)
    if not results:
        print("OK: every mermaid classDef in %s reads at >= %.1f:1 in both "
              "palettes, and the RFX-268 mechanism is in place." % (docs, MIN_CONTRAST))
    sys.exit(1 if results else 0)
