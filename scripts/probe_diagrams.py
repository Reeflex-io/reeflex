#!/usr/bin/env python3
"""probe_diagrams.py — measure what a reader actually SEES on a built docs page.

Renders the built site in Chromium and measures, per mermaid diagram, in BOTH
palettes: natural width, effective label size, and the PAINTED contrast of every
label, read out of the screenshot's pixels.

WHY THIS FILE IS IN THE REPO (RFX-266). Between 2026-09-10 and 2026-09-11 four
separate rounds each wrote a throwaway harness for this one site, used it once
and left it in a report folder: a render harness, `measure-labels.py`, a
`probe-contrast.py` whose selector was one node too high, and
`probe-painted-pixels.py`. Three of the defects those rounds found were not in
the docs at all — they were in the instrument. This file is the fifth harness
and is meant to be the last: every trap below is a measured one, and every one
of them is now a behaviour rather than a paragraph in a report nobody rereads.

  TRAP 1 — `div.mermaid svg` IS A FALSE FAIL. mkdocs-material 9.7.7 renders each
  diagram into a shadow root opened with `mode: "closed"`, so the host div lays
  out at the diagram's full height while `host.shadowRoot` is null, `innerHTML`
  is "" and Playwright's shadow-piercing selectors do not pierce it either. The
  naive query returns 6 divs and 0 svgs on a page showing all six drawn. This
  probe forces `attachShadow` to `open` (mode governs script access, not layout,
  style scoping or paint) and RECORDS the naive count side by side with the true
  one in every run, so the false reading stays visible instead of being
  rediscovered. See `shadow_pierced` / `svgs_by_naive_query` in the JSON.

  TRAP 2 — `mermaid.render(<source extracted from the markdown>)` IS A FALSE
  PASS. It proves the diagram source parses. The page can still paint it at 5px,
  in the wrong colour, or not at all. This probe never re-renders anything: it
  measures the page the build produced. There is deliberately no code path here
  that takes mermaid source as an input.

  TRAP 3 — AN INJECTED PALETTE IS SILENTLY WIPED. `overrides/main.html` runs a
  one-time migration in `<head>` that deletes every localStorage key containing
  `__palette` unless `__rf_palette_migrated_v2` is set. Setting the scheme
  without that flag first measures `default` twice and calls it "both palettes".
  This probe sets the flag first AND asserts `data-md-color-scheme` on the
  rendered body; a mismatch is a finding, not a log line.

  TRAP 4 — `document.fonts.check('16px Inter')` RETURNS TRUE WITH THE WEBFONT
  BLOCKED. `check()` is true when no matching `@font-face` rule exists at all,
  which is exactly the state a blocked CDN produces. Measured on this site:
  fonts allowed -> 9 loaded faces, `check` true; fonts blocked -> 0 loaded
  faces, `check` STILL true. The honest signal is the count of faces whose
  status is `loaded`, and that is what `webfont_faces_loaded` reports.

  TRAP 5 — THE FONT REGIME MOVES THE GEOMETRY, AND IT IS NOT A SETTLING DELAY.
  `theme.font.text: Inter` is fetched from fonts.googleapis.com, so a host that
  cannot reach it renders with fallback metrics. On docs/architecture/diagrams.md
  the six natural widths are 1130/931/749/439/841/873 with Inter and
  1166/959/773/451/850/892 without — up to +3.2%, which moves every effective
  label size derived from them. An earlier round recorded those two number-sets
  as an early-vs-late SETTLING difference; sampling the same page load at
  1.0/1.5/3.5/6.0/9.0s shows each regime FLAT at its own series from one second
  on, so the variable is the font, not the clock. The regime is therefore
  recorded in every result and, under `--require-webfont`, a missing webfont is
  an instrument failure rather than a quietly different number. Fallback metrics
  make diagrams WIDER, hence scaled down further, hence labels SMALLER, so a
  font outage can only cost a false FAIL on label size — never a false pass.

  TRAP 6 — SMALL TEXT UNDER-READS AT deviceScaleFactor=1. A label 8 CSS px tall
  is mostly antialiasing, and a pixel sampler with a count floor can miss the
  glyph core entirely (one round read a plainly white autonumber as 1.00:1).
  This probe renders at deviceScaleFactor=3, so the same glyph is ~24 device
  pixels and has a solid core, and reports `px`/`distinct` per sample so any
  reading can be audited.

ONE AUTHORITY, NOT TWO. `check_diagram_contrast.py` is the fast static check
that runs inside every `mkdocs build` as a `hooks:` entry; it reads the markdown
and the CSS and models what mermaid + Material do with a classDef. Its stated
hole is that a Material or mermaid upgrade could change the mechanism without
changing any file it reads. This probe closes that hole rather than competing
with it: it IMPORTS that module's colour parsing, contrast function, palette
reader, classDef reader and threshold — there is one definition of each — and
then falsifies its model against the pixels (check `ink-identity` below).

WHAT IT CHECKS
  render         every `.mermaid` host produced an SVG
  palette        the palette under measurement is the one that rendered
  webfont        at least one @font-face actually loaded (gated by --require-webfont)
  contrast       painted contrast of every diagram label >= the shared threshold
  ink-identity   a node's painted ink is nearer its classDef's declared `color:`
                 than the palette ink — the pixel proof that the RFX-268
                 mechanism still reaches the element that paints
  label-size     effective label size >= --min-eff-label-px

THE BASELINE IS A WORKLIST, NOT A WAIVER LIST. This probe found defects on its
first run against main that the four throwaway harnesses had missed, because all
four looked only at docs/architecture/diagrams.md. Fixing them is a content
change and this is a tooling change, so they are recorded in
`scripts/diagram_probe_baseline.json` with the ticket that tracks each one, and
the recording is deliberately hostile to being forgotten:

  * a finding whose key is NOT in the baseline fails the run;
  * a finding whose key IS in the baseline but which got worse — a lower
    contrast, a smaller label, or more labels affected — fails the run;
  * a baseline entry that produces NO finding also fails the run, as
    `baseline-stale`. A fixed defect cannot sit in this file as a permanent
    exemption; the file can only shrink.

The `worst` comparison allows 5%, which is the measured width of the font-regime
difference in TRAP 5. Under `--require-webfont` that slack is not needed and the
numbers are stable to the pixel.

WHAT IT CANNOT SEE
  * One viewport. `--viewport` changes it; the default 1440 is the laptop case
    and a 400px-wide reader gets every scaled diagram at roughly half these
    effective sizes.
  * Contrast is read as a LOWER BOUND: the ink is the sampled colour furthest in
    luminance from the modal background, among colours meeting a count floor, so
    a hairline-thin glyph reads lower than it is. Low readings are worth
    checking by eye against the screenshot; high readings are trustworthy.
  * It measures the built site it is given. It says nothing about whether that
    site is the one published.

Usage:
  python scripts/probe_diagrams.py SITE_DIR [options]
    --palettes default,slate     palettes to measure (default: both)
    --viewport 1440              viewport width in CSS px
    --min-eff-label-px 7.5       effective-label-size floor
    --require-webfont            a missing webfont is a finding
    --json OUT.json              write the full measurement
    --screenshots DIR            keep the full-page PNGs and per-diagram crops
    --docs-dir DOCS              markdown+CSS source (default: ./docs)
  exit 0 = clean, 1 = findings, 2 = the instrument could not measure at all.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import socketserver
import sys
import threading
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ONE definition of the colour maths, the threshold, the palette reader and the
# classDef reader — this probe is the pixel half of that module, not a rival.
from check_diagram_contrast import (  # noqa: E402
    MIN_CONTRAST,
    contrast_ratio,
    iter_classdefs,
    parse_hex,
    read_palette_vars,
    relative_luminance,
)

PALETTE_INK_VARS = ("--rfx-mermaid-ink", "--md-mermaid-label-fg-color")
BODY_INK_VARS = ("--md-default-fg-color",)

# Two candidate inks closer than this in RGB cannot be told apart in the blend
# pixels around a small glyph, so `ink-identity` declines to judge rather than
# guessing. This is why the probe does NOT close RFX-273: the state that ticket
# describes (the `.mermaid` host's own `color:` deleted, so an uncoloured label
# inherits body ink instead of mermaid ink) is a swap between colours that are
# only 24.9 RGB apart in `default` and 31.4 in `slate` — measured, both under
# this floor. A pixel probe is the wrong instrument for that one; the static
# check in check_diagram_contrast.py is the right place and RFX-273 stays open.
INK_IDENTITY_MIN_GAP = 40

# Pages that carry mermaid fences, as (built URL path, source markdown).
# Discovered from the docs dir at run time; this is only the fallback ordering.
DEFAULT_DOCS_DIR = "docs"


# ---------------------------------------------------------------------------
# browser-side scripts
# ---------------------------------------------------------------------------

# TRAP 1. Opening the shadow root is what makes any of this measurable.
# Geometry-neutral: with and without it the six diagram heights on
# architecture/diagrams.md are identical at the same settle time.
PIERCE = """
(() => {
  const orig = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (init) {
    const r = orig.call(this, Object.assign({}, init, { mode: 'open' }));
    this.setAttribute('data-rfx-pierced', '1');
    return r;
  };
})();
"""

# TRAP 3. The migration in overrides/main.html deletes every `__palette` key
# unless this flag is already set, so the flag goes first.
PALETTE_TMPL = (
    "localStorage.setItem('__rf_palette_migrated_v2','1');"
    "localStorage.setItem('/.__palette', JSON.stringify("
    "{index: %d, color: {media: '', scheme: '%s',"
    " primary: 'custom', accent: 'custom'}}));"
)

# Layout is flat from ~1s within a font regime (TRAP 5), but a slow local file
# server or a cold JS bundle can still be mid-render, so wait for the heights to
# stop moving rather than for a fixed delay.
SETTLE = """
() => new Promise(res => {
  let last = '', stable = 0, ticks = 0;
  const tick = () => {
    const now = [...document.querySelectorAll('.mermaid')]
      .map(h => Math.round(h.getBoundingClientRect().height)).join(',');
    stable = (now === last && now !== '') ? stable + 1 : 0;
    last = now;
    if (stable >= 3 || ++ticks > 40) return res(now);
    setTimeout(tick, 250);
  };
  document.fonts.ready.then(() => setTimeout(tick, 1000));
})
"""

COLLECT = r"""
() => {
  const out = {
    // TRAP 1, kept in every run: the false reading next to the true one.
    mermaid_divs: document.querySelectorAll('div.mermaid').length,
    svgs_by_naive_query: document.querySelectorAll('div.mermaid svg').length,
    shadow_pierced: document.querySelectorAll('[data-rfx-pierced]').length,
    // TRAP 4: the count of LOADED faces, not document.fonts.check().
    webfont_faces_loaded: [...document.fonts].filter(f => f.status === 'loaded').length,
    webfont_check_says: document.fonts.check('16px Inter'),
    palette_asserted: document.body.getAttribute('data-md-color-scheme'),
    content_column_px: (() => {
      const c = document.querySelector('.md-content__inner');
      return c ? Math.round(c.getBoundingClientRect().width) : null;
    })(),
    diagrams: [],
  };

  const hosts = [...document.querySelectorAll('.mermaid')];
  hosts.forEach((host, di) => {
    const root = host.shadowRoot || host;
    const svg = root.querySelector('svg');
    const hr = host.getBoundingClientRect();
    const d = {
      index: di,
      svg_id: svg ? (svg.id || null) : null,
      kind: svg ? (svg.getAttribute('aria-roledescription') || 'unknown') : null,
      rendered: !!svg,
      heading: null,
      host_box: [hr.left + scrollX, hr.top + scrollY, hr.right + scrollX, hr.bottom + scrollY],
      labels: [],
    };

    // Nearest preceding heading, walking out of the shadow root first.
    for (let el = host; el && !d.heading; el = el.parentElement) {
      for (let p = el.previousElementSibling; p; p = p.previousElementSibling) {
        const h = (p.tagName || '').match(/^H[1-6]$/) ? p
          : (p.querySelectorAll ? [...p.querySelectorAll('h1,h2,h3')].pop() : null);
        if (h) { d.heading = h.textContent.replace(/[\s¶]+/g, ' ').trim(); break; }
      }
    }

    if (svg) {
      const box = svg.getBoundingClientRect();
      // Intrinsic width: mermaid writes style="max-width: Npx"; the viewBox is
      // the authoritative user-space size when it does not.
      let natural = parseFloat((svg.style.maxWidth || '').replace('px', ''));
      const vb = svg.viewBox && svg.viewBox.baseVal;
      if (!natural && vb && vb.width) natural = vb.width;
      d.natural_w = natural ? Math.round(natural * 100) / 100 : null;
      d.rendered_w = Math.round(box.width * 100) / 100;
      d.rendered_h = Math.round(box.height * 100) / 100;
      // CSS max-width:100% shrinks a diagram wider than the reading column, and
      // shrinks its text with it. This is the whole reason effective size is
      // not the computed font-size.
      d.scale = natural ? Math.round((box.width / natural) * 1000) / 1000 : null;

      // <p> = foreignObject label (flowchart / state node, cluster, edge).
      // <text> = native SVG text (sequence diagrams, some state labels).
      for (const el of root.querySelectorAll('p, text')) {
        const t = (el.textContent || '').trim();
        if (!t) continue;
        const r = el.getBoundingClientRect();
        if (r.width < 1 || r.height < 1) continue;
        const cs = getComputedStyle(el);
        const fs = parseFloat(cs.fontSize);
        if (!fs) continue;

        // Which kind of label is this, and which classDef classes does its
        // owning node carry? mermaid puts classDef ids in the <g class="node ...">
        // token list; cluster and edge labels are NOT classDef-addressable.
        let role = 'other', classes = [];
        for (let n = el; n && n !== root; n = n.parentElement || n.parentNode) {
          const cl = (n.getAttribute && n.getAttribute('class') || '').split(/\s+/).filter(Boolean);
          if (!cl.length) continue;
          if (cl.includes('cluster-label') || cl.includes('cluster')) { role = 'cluster'; break; }
          if (cl.includes('edgeLabel') || cl.includes('edgeLabels')) { role = 'edge'; break; }
          if (cl.includes('actor') || cl.includes('actor-box')) { role = 'actor'; break; }
          if (cl.includes('node') || cl.some(c => c.startsWith('statediagram-'))) {
            role = 'node';
            classes = cl.filter(c => !['node', 'default', 'label', 'nodes',
                                       'statediagram-state', 'flowchart-label',
                                       'clickable'].includes(c));
            break;
          }
        }

        d.labels.push({
          text: t.slice(0, 60),
          tag: el.tagName.toLowerCase(),
          role: role,
          classes: classes,
          declared_font_px: Math.round(fs * 100) / 100,
          eff_font_px: d.scale ? Math.round(fs * d.scale * 100) / 100 : null,
          // Recorded to be CONTRADICTED by the pixels, never used as a verdict:
          // reading this instead of the paint is how two rounds reported ~9:1
          // over a page painting 1.3:1.
          css_color: cs.color,
          box: [r.left + scrollX, r.top + scrollY, r.right + scrollX, r.bottom + scrollY],
        });
      }
    }
    out.diagrams.push(d);
  });
  return out;
}
"""


# ---------------------------------------------------------------------------
# pixel sampling
# ---------------------------------------------------------------------------
def sample_ink(img, box, dsf):
    """(bg, ink, contrast, n_px) from the painted pixels of one label's box.

    bg  = the modal colour in the box (the node fill behind the text)
    ink = the colour furthest from bg in relative luminance, among colours whose
          pixel count clears a floor — the floor stops a single antialiasing
          outlier from being reported as the text colour.
    The result is a LOWER BOUND on the true contrast: a thin glyph is mostly
    blend pixels, which sit between ink and background.
    """
    x0, y0, x1, y1 = (int(round(v * dsf)) for v in box)
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(img.width, x1), min(img.height, y1)
    if x1 - x0 < 1 or y1 - y0 < 1:
        return None
    px = list(img.crop((x0, y0, x1, y1)).convert("RGB").getdata())
    if not px:
        return None
    counts = Counter(px)
    bg = counts.most_common(1)[0][0]
    floor = max(3, int(0.003 * len(px)))
    ink, best = bg, -1.0
    lbg = relative_luminance(bg)
    for colour, n in counts.items():
        if n < floor:
            continue
        delta = abs(relative_luminance(colour) - lbg)
        if delta > best:
            best, ink = delta, colour
    return {
        "bg": "#%02x%02x%02x" % bg,
        "ink": "#%02x%02x%02x" % ink,
        "bg_rgb": list(bg),
        "ink_rgb": list(ink),
        "cr": round(contrast_ratio(ink, bg), 2),
        "px": len(px),
        "distinct": len(counts),
        "floor": floor,
    }


def rgb_distance(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5


def _hexs(rgb):
    return "#%02x%02x%02x" % tuple(rgb)


# ---------------------------------------------------------------------------
# source side: which pages have diagrams, and what each classDef declares
# ---------------------------------------------------------------------------
def discover_pages(docs_dir):
    """[(url_path, source_relpath)] for every markdown file with a mermaid fence."""
    pages = []
    for root, _dirs, files in os.walk(docs_dir):
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as fh:
                if "```mermaid" not in fh.read():
                    continue
            rel = os.path.relpath(path, docs_dir).replace(os.sep, "/")
            stem = rel[:-3]
            url = "" if stem == "index" else (
                stem[:-6] if stem.endswith("/index") else stem)
            pages.append((url, "docs/" + rel))
    return sorted(pages)


def classdef_colours(docs_dir):
    """{class_id: {'color': '#fff', 'fill': '#7f1d1d', 'where': 'docs/x.md:159'}}"""
    out = {}
    for root, _dirs, files in os.walk(docs_dir):
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            path = os.path.join(root, name)
            rel = "docs/" + os.path.relpath(path, docs_dir).replace(os.sep, "/")
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for line_no, ids, props in iter_classdefs(text):
                for cid in ids:
                    out[cid] = {"color": props.get("color"),
                                "fill": props.get("fill"),
                                "where": "%s:%d" % (rel, line_no)}
    return out


def css_colour_by_scheme(docs_dir, var_names):
    """{'default': (r,g,b) or None, 'slate': ...} for the first var that parses."""
    css_path = os.path.join(docs_dir, "stylesheets", "extra.css")
    try:
        with open(css_path, encoding="utf-8") as fh:
            css = fh.read()
    except OSError:
        return {}
    out = {}
    for scheme, vars_ in read_palette_vars(css).items():
        rgb = None
        for var in var_names:
            raw = vars_.get(var)
            rgb = parse_hex(raw) if raw else None
            if rgb is not None:
                break
        out[scheme] = rgb
    return out


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------
def serve(site_dir):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=site_dir)

    class Quiet(socketserver.TCPServer):
        allow_reuse_address = True

        def handle_error(self, *a):
            pass

    # Port 0 == ephemeral and the server is shut down in-process: this probe
    # never leaves a listener behind for someone else to find.
    httpd = Quiet(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def measure(site_dir, pages, palettes, viewport, dsf, shots_dir):
    from PIL import Image
    from playwright.sync_api import sync_playwright

    httpd, port = serve(site_dir)
    results = {"site_dir": os.path.abspath(site_dir), "viewport_px": viewport,
               "device_scale_factor": dsf, "runs": {}}
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox"])
            # Recorded because every number below is an artefact of this
            # renderer: a Chromium bump can move geometry the way a font regime
            # does, and a JSON with no engine version in it cannot be compared
            # to an older one.
            results["chromium_version"] = browser.version
            for palette in palettes:
                ctx = browser.new_context(
                    viewport={"width": viewport, "height": 900},
                    device_scale_factor=dsf)
                # Palette before first paint: mermaid bakes theme values at
                # render time, so flipping afterwards measures a half-applied page.
                ctx.add_init_script(PALETTE_TMPL % (
                    0 if palette == "default" else 1, palette))
                ctx.add_init_script(PIERCE)
                page = ctx.new_page()
                run = {}
                for url_path, src in pages:
                    url = "http://127.0.0.1:%d/%s" % (port, url_path + "/" if url_path else "")
                    page.goto(url, wait_until="networkidle")
                    settled = page.evaluate(SETTLE)
                    page.wait_for_timeout(200)
                    shot = os.path.join(
                        shots_dir, "page--%s--%s.png"
                        % ((url_path or "index").replace("/", "_"), palette))
                    page.screenshot(path=shot, full_page=True)
                    data = page.evaluate(COLLECT)
                    img = Image.open(shot)
                    for d in data["diagrams"]:
                        for lab in d["labels"]:
                            lab["painted"] = sample_ink(img, lab["box"], dsf)
                        effs = [l["eff_font_px"] for l in d["labels"]
                                if l["eff_font_px"]]
                        d["min_eff_font_px"] = round(min(effs), 2) if effs else None
                        d["max_eff_font_px"] = round(max(effs), 2) if effs else None
                    data["settled_heights"] = settled
                    data["src"] = src
                    data["url_path"] = url_path
                    data["screenshot"] = os.path.basename(shot)
                    run[url_path or "index"] = data
                ctx.close()
                results["runs"][palette] = run
            browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
    return results


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------
def evaluate(results, docs_dir, min_eff_label_px, require_webfont):
    """List of finding dicts. `severity` FAIL counts against the exit code."""
    findings, skipped = [], []
    declared = classdef_colours(docs_dir)
    pal_ink = css_colour_by_scheme(docs_dir, PALETTE_INK_VARS)
    body_ink = css_colour_by_scheme(docs_dir, BODY_INK_VARS)

    def add(check, severity, src, palette, diagram, label, value, message):
        findings.append({"check": check, "severity": severity, "src": src,
                         "palette": palette, "diagram": diagram, "label": label,
                         "value": value, "message": message})

    for palette, run in sorted(results["runs"].items()):
        for _key, page in sorted(run.items()):
            src = page["src"]
            where = "%s [%s]" % (src, palette)

            # --- palette ----------------------------------------------------
            if page["palette_asserted"] != palette:
                add("palette", "FAIL", src, palette, None, None, None,
                    "%s — asked for the %r palette and the page rendered %r. "
                    "Nothing below describes the palette it claims to. "
                    "(overrides/main.html deletes every `__palette` key unless "
                    "`__rf_palette_migrated_v2` is set first.)"
                    % (where, palette, page["palette_asserted"]))

            # --- webfont ----------------------------------------------------
            if page["webfont_faces_loaded"] == 0:
                add("webfont", "FAIL" if require_webfont else "WARN",
                    src, palette, None, None, None,
                    "%s — no @font-face loaded, so every size below is FALLBACK "
                    "metrics, not what a reader with Inter gets (measured: up to "
                    "+3.2%% natural width, i.e. smaller effective labels). "
                    "`document.fonts.check('16px Inter')` says %s here and is not "
                    "a usable signal — it is true precisely because there is no "
                    "@font-face rule to fail."
                    % (where, page["webfont_check_says"]))

            for d in page["diagrams"]:
                name = d["heading"] or ("diagram %d" % d["index"])

                # --- render -------------------------------------------------
                if not d["rendered"]:
                    add("render", "FAIL", src, palette, name, None, None,
                        "%s — %r produced no SVG inside its `.mermaid` host. "
                        "This is read through a forced-open shadow root, so it "
                        "is not the `div.mermaid svg` false FAIL: the host is "
                        "there and empty." % (where, name))
                    continue

                for lab in d["labels"]:
                    # --- label-size ----------------------------------------
                    eff = lab["eff_font_px"]
                    if eff is not None and eff < min_eff_label_px:
                        add("label-size", "FAIL", src, palette, name,
                            lab["text"], eff,
                            "%s — %r label %r renders at %.2f px effective "
                            "(%.0f px declared x %.3f shrink: the diagram is "
                            "%s px wide in a %s px column), under the %.1f px "
                            "floor."
                            % (where, name, lab["text"], eff,
                               lab["declared_font_px"], d["scale"],
                               d["natural_w"], page["content_column_px"],
                               min_eff_label_px))

                    p = lab["painted"]
                    if p is None:
                        continue

                    # --- contrast ------------------------------------------
                    if p["cr"] < MIN_CONTRAST:
                        add("contrast", "FAIL", src, palette, name,
                            lab["text"], p["cr"],
                            "%s — %r label %r paints %s on %s = %.2f:1, under "
                            "WCAG 1.4.3's %.1f:1. Computed style claims %s; the "
                            "pixels are the verdict. (%d px sampled, %d distinct)"
                            % (where, name, lab["text"], p["ink"], p["bg"],
                               p["cr"], MIN_CONTRAST, lab["css_color"],
                               p["px"], p["distinct"]))

                    # --- ink-identity --------------------------------------
                    # A node label must paint the ink it was told to paint: its
                    # classDef's `color:` when it has one, otherwise the palette
                    # ink. Either way the OTHER of those two is the colour it
                    # reverts to when the mechanism breaks, so the test is which
                    # of the two the painted pixel is nearer.
                    if lab["role"] != "node":
                        continue
                    fallback = pal_ink.get(palette)
                    if fallback is None:
                        continue
                    hit = [c for c in lab["classes"] if c in declared
                           and parse_hex(declared[c].get("color") or "")]
                    if hit:
                        cid = hit[0]
                        want = parse_hex(declared[cid]["color"])
                        other, other_name = fallback, "the palette ink"
                        told = "classDef `%s` (%s, color:%s)" % (
                            cid, declared[cid]["where"], declared[cid]["color"])
                    else:
                        want = fallback
                        other = body_ink.get(palette)
                        other_name = "the body text ink"
                        told = "no classDef colour, so the palette ink %s" % _hexs(fallback)
                    if other is None:
                        continue
                    gap = rgb_distance(want, other)
                    if gap < INK_IDENTITY_MIN_GAP:
                        # The two candidate inks are closer than the blend
                        # pixels around a small glyph, so this test would be a
                        # coin toss. Recorded, not silently skipped.
                        skipped.append(
                            "%s — %r: ink-identity not applicable, the two "
                            "candidate inks (%s and %s, %s) are %.1f RGB apart, "
                            "under the %d floor."
                            % (where, name, _hexs(want), _hexs(other),
                               other_name, gap, INK_IDENTITY_MIN_GAP))
                        continue
                    d_want = rgb_distance(p["ink_rgb"], want)
                    d_other = rgb_distance(p["ink_rgb"], other)
                    if d_want > d_other:
                        add("ink-identity", "FAIL", src, palette, name,
                            lab["text"], None,
                            "%s — %r node %r was told to paint %s but paints "
                            "%s, which is nearer %s %s (distance %.0f) than "
                            "what it was told (distance %.0f). The ink is not "
                            "reaching the element that paints: check that a "
                            "`.mermaid` rule still sets "
                            "`--md-mermaid-label-fg-color: currentColor` and "
                            "still sets `color:` to the palette ink."
                            % (where, name, lab["text"], told, p["ink"],
                               other_name, _hexs(other), d_other, d_want))
    results["ink_identity_skipped"] = sorted(set(skipped))
    return findings


# ---------------------------------------------------------------------------
# the baseline ratchet
# ---------------------------------------------------------------------------
# Only the two checks with a number worth comparing can be baselined. `render`,
# `palette`, `webfont` and `ink-identity` are instrument or mechanism failures:
# there is no "known amount" of them and no entry in the file can excuse one.
BASELINEABLE = {"label-size", "contrast"}
BASELINE_SLACK = 0.05   # the measured width of the font-regime difference


def _bkey(f):
    return "%s|%s|%s|%s" % (f["check"], f["src"], f["palette"], f["diagram"])


def load_baseline(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return {"%s|%s|%s|%s" % (e["check"], e["src"], e["palette"], e["diagram"]): e
            for e in doc.get("known", [])}


def apply_baseline(findings, baseline, path):
    """Downgrade known findings, fail on regressions, fail on stale entries."""
    if not baseline:
        return findings
    out, grouped = [], {}
    for f in findings:
        if f["check"] in BASELINEABLE and _bkey(f) in baseline:
            grouped.setdefault(_bkey(f), []).append(f)
        else:
            out.append(f)

    for key, entry in sorted(baseline.items()):
        group = grouped.get(key)
        if not group:
            out.append({
                "check": "baseline-stale", "severity": "FAIL",
                "src": entry["src"], "palette": entry["palette"],
                "diagram": entry["diagram"], "label": None, "value": None,
                "message":
                    "%s [%s] — %r is recorded in %s as a known %s defect "
                    "(%s) and the probe no longer reproduces it. If it was "
                    "fixed, DELETE the entry; this file is a worklist and may "
                    "only shrink. If the probe stopped looking, that is worse."
                    % (entry["src"], entry["palette"], entry["diagram"], path,
                       entry["check"], entry.get("ticket", "no ticket"))})
            continue

        # "worst" is the smallest number, for both checks: the smallest
        # effective label and the lowest contrast are the worst cases.
        worst = min(f["value"] for f in group)
        allowed = entry["worst"] * (1 - BASELINE_SLACK)
        if worst < allowed:
            out.append({
                "check": entry["check"], "severity": "FAIL",
                "src": entry["src"], "palette": entry["palette"],
                "diagram": entry["diagram"], "label": None, "value": worst,
                "message":
                    "%s [%s] — %r got WORSE: the baseline in %s records %.2f "
                    "and this run measures %.2f (below the %.0f%% slack floor "
                    "of %.2f). A known defect is allowed to stay; it is not "
                    "allowed to deepen. Ticket %s."
                    % (entry["src"], entry["palette"], entry["diagram"], path,
                       entry["worst"], worst, BASELINE_SLACK * 100, allowed,
                       entry.get("ticket", "(none)"))})
            continue

        if len(group) > entry["labels"]:
            out.append({
                "check": entry["check"], "severity": "FAIL",
                "src": entry["src"], "palette": entry["palette"],
                "diagram": entry["diagram"], "label": None, "value": None,
                "message":
                    "%s [%s] — %r SPREAD: the baseline in %s records %d "
                    "affected label(s) and this run finds %d. Ticket %s."
                    % (entry["src"], entry["palette"], entry["diagram"], path,
                       entry["labels"], len(group), entry.get("ticket", "(none)"))})
            continue

        out.append({
            "check": entry["check"], "severity": "KNOWN",
            "src": entry["src"], "palette": entry["palette"],
            "diagram": entry["diagram"], "label": None, "value": worst,
            "message":
                "%s [%s] — %r: %d label(s), worst %.2f (baseline %.2f). "
                "Tracked by %s: %s"
                % (entry["src"], entry["palette"], entry["diagram"],
                   len(group), worst, entry["worst"],
                   entry.get("ticket", "(no ticket)"), entry.get("note", ""))})
    return out


# ---------------------------------------------------------------------------
def summarise(results, out=sys.stdout):
    for palette, run in sorted(results["runs"].items()):
        for key, page in sorted(run.items()):
            print("== %s  palette=%s  column=%spx  webfont_faces=%d  "
                  "pierced=%d/%d  naive `div.mermaid svg`=%d"
                  % (page["src"], page["palette_asserted"],
                     page["content_column_px"], page["webfont_faces_loaded"],
                     page["shadow_pierced"], page["mermaid_divs"],
                     page["svgs_by_naive_query"]), file=out)
            for d in page["diagrams"]:
                if not d["rendered"]:
                    print("   %-52s NOT RENDERED" % (d["heading"] or d["index"]), file=out)
                    continue
                crs = [l["painted"]["cr"] for l in d["labels"]
                       if l.get("painted")]
                print("   %-52.52s nat=%-8s rend=%-6s scale=%-6s "
                      "eff=%.2f-%.2f px  painted CR %.2f-%.2f  n=%d"
                      % (d["heading"] or ("diagram %d" % d["index"]),
                         d["natural_w"], d["rendered_w"], d["scale"],
                         d["min_eff_font_px"] or 0, d["max_eff_font_px"] or 0,
                         min(crs) if crs else 0, max(crs) if crs else 0,
                         len(d["labels"])), file=out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("site_dir")
    ap.add_argument("--palettes", default="default,slate")
    ap.add_argument("--viewport", type=int, default=1440)
    ap.add_argument("--device-scale-factor", type=int, default=3)
    ap.add_argument("--min-eff-label-px", type=float, default=10.0)
    ap.add_argument("--require-webfont", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--screenshots")
    ap.add_argument("--docs-dir", default=DEFAULT_DOCS_DIR)
    ap.add_argument("--baseline", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "diagram_probe_baseline.json"),
        help="known-defect worklist; --baseline '' disables it")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.site_dir):
        print("probe_diagrams: %s is not a directory. Build the site first "
              "(`mkdocs build -d site`) — this probe measures the BUILT page, "
              "never the markdown source." % args.site_dir, file=sys.stderr)
        return 2

    pages = discover_pages(args.docs_dir)
    if not pages:
        print("probe_diagrams: no markdown under %s contains a ```mermaid "
              "fence, so there is nothing to measure. That is an instrument "
              "failure, not a clean run." % args.docs_dir, file=sys.stderr)
        return 2

    shots = args.screenshots or os.path.join(
        os.environ.get("TMPDIR", "/tmp"), "rfx-probe-diagrams")
    os.makedirs(shots, exist_ok=True)

    try:
        results = measure(args.site_dir, pages,
                          [p.strip() for p in args.palettes.split(",") if p.strip()],
                          args.viewport, args.device_scale_factor, shots)
    except Exception as exc:                       # noqa: BLE001
        print("probe_diagrams: could not render at all (%s: %s). A probe that "
              "cannot render reports NOTHING, which is not the same as a clean "
              "page." % (type(exc).__name__, exc), file=sys.stderr)
        return 2

    findings = evaluate(results, args.docs_dir, args.min_eff_label_px,
                        args.require_webfont)
    findings = apply_baseline(findings, load_baseline(args.baseline),
                              args.baseline or "(no baseline)")
    results["findings"] = findings
    results["baseline"] = args.baseline or None

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=1)

    summarise(results)
    print()
    rank = {"FAIL": 0, "WARN": 1, "KNOWN": 2}
    for f in sorted(findings, key=lambda f: (rank.get(f["severity"], 3),
                                             f["check"], f["src"])):
        print("%-5s [%s] %s" % (f["severity"], f["check"], f["message"]))
    fails = [f for f in findings if f["severity"] == "FAIL"]
    if not fails:
        print("\nOK: %d page(s) x %d palette(s) rendered; every diagram label "
              "reads at >= %.1f:1 painted, carries its own classDef ink, and "
              "renders at >= %.1f px effective — except the %d entr(y/ies) "
              "listed as KNOWN above, each of which is ticketed and may not "
              "deepen."
              % (len(pages), len(results["runs"]), MIN_CONTRAST,
                 args.min_eff_label_px,
                 len([f for f in findings if f["severity"] == "KNOWN"])))
    print("\nscreenshots: %s" % shots)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
