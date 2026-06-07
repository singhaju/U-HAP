#!/usr/bin/env python3
"""
build_pptx.py  —  Rebuild U-HAP 21-slide conference presentation as a
fully editable PPTX file using python-pptx.

Every element (text boxes, shapes, tables) is a native PPTX object.
"""

import os
import sys
import copy
from pathlib import Path
from PIL import Image as PILImage
from lxml import etree

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.oxml.ns import qn
from pptx.oxml import parse_xml
from pptx.util import Inches, Pt

# ── Paths ───────────────────────────────────────────────────────────────────
BASE = Path("/home/singhaj/Documents/SIIT/U-HAP/presentation")
FIG  = BASE / "figures"
PNG  = BASE / "slides_png"
OUT  = BASE / "slides_uhap_editable.pptx"
TMP  = Path("/tmp/hash_diagram_crop.png")

# ── Colour palette ──────────────────────────────────────────────────────────
NAVY     = RGBColor(0x0E, 0x2A, 0x4A)
NAVY_D   = RGBColor(0x08, 0x1A, 0x30)
TEAL     = RGBColor(0x00, 0x89, 0x7B)
AMBER_BG = RGBColor(0xFF, 0xF8, 0xE1)
AMBER_BDR= RGBColor(0xF5, 0x7F, 0x17)
GRAY     = RGBColor(0xF5, 0xF5, 0xF5)
GRAY_D   = RGBColor(0x54, 0x6E, 0x7A)
GREEN    = RGBColor(0x2E, 0x7D, 0x32)
RED      = RGBColor(0xC6, 0x28, 0x28)
WHITE    = RGBColor(0xFF, 0xFF, 0xFF)
BLACK    = RGBColor(0x00, 0x00, 0x00)

# ── Slide geometry ──────────────────────────────────────────────────────────
W          = Inches(10)
H          = Inches(5.625)
HDR_H      = Inches(0.6)
FTR_H      = Inches(0.32)
CONTENT_T  = Inches(0.65)
CONTENT_H  = Inches(4.63)
LMARGIN    = Inches(0.28)
RMARGIN    = Inches(0.28)
USABLE_W   = Inches(9.44)

# ── Warnings log ────────────────────────────────────────────────────────────
WARNINGS = []


# ════════════════════════════════════════════════════════════════════════════
# LOW-LEVEL HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _rgb_hex(color: RGBColor) -> str:
    return f"{color[0]:02X}{color[1]:02X}{color[2]:02X}"


def add_rect(slide, left, top, width, height,
             fill_color=None, line_color=None, line_pt=0.75,
             rounded=False):
    """Add a rectangle (optionally rounded) with optional fill and border."""
    shape = slide.shapes.add_shape(
        1,  # MSO_SHAPE_TYPE.RECTANGLE
        left, top, width, height
    )
    # Fill
    if fill_color is None:
        shape.fill.background()
    else:
        shape.fill.solid()
        shape.fill.fore_color.rgb = fill_color
    # Line
    if line_color is None:
        shape.line.fill.background()
    else:
        shape.line.color.rgb = line_color
        shape.line.width = Pt(line_pt)
    # Rounded corners via XML
    if rounded:
        sp = shape.element
        spPr = sp.find(qn('p:spPr'))
        if spPr is not None:
            prstGeom = spPr.find(qn('a:prstGeom'))
            if prstGeom is not None:
                prstGeom.set('prst', 'roundRect')
                avLst = prstGeom.find(qn('a:avLst'))
                if avLst is None:
                    avLst = etree.SubElement(prstGeom, qn('a:avLst'))
                gd = etree.SubElement(avLst, qn('a:gd'))
                gd.set('name', 'adj')
                gd.set('fmla', 'val 20000')
    return shape


def add_textbox(slide, left, top, width, height, text,
                font_pt=9, bold=False, italic=False,
                color=NAVY_D, align=PP_ALIGN.LEFT,
                wrap=True, font_name="Calibri"):
    """Add a simple text box."""
    txb = slide.shapes.add_textbox(left, top, width, height)
    tf  = txb.text_frame
    tf.word_wrap = wrap
    p   = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size  = Pt(font_pt)
    run.font.bold  = bold
    run.font.italic = italic
    run.font.color.rgb = color
    run.font.name  = font_name
    return txb


def set_run(run, text, font_pt=9, bold=False, italic=False,
            color=NAVY_D, font_name="Calibri"):
    run.text = text
    run.font.size = Pt(font_pt)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    run.font.name = font_name


def add_picture_safe(slide, path, left, top, height):
    """Insert picture; warn and skip if file missing."""
    if not Path(path).exists():
        WARNINGS.append(f"Missing image: {path}")
        return None
    return slide.shapes.add_picture(str(path), left, top, height=height)


# ════════════════════════════════════════════════════════════════════════════
# HEADER / FOOTER
# ════════════════════════════════════════════════════════════════════════════

def add_header(slide, title_text):
    """Full-width navy header bar with white title."""
    bar = add_rect(slide, 0, 0, W, HDR_H, fill_color=NAVY)
    bar.name = "HeaderBar"
    txb = slide.shapes.add_textbox(Inches(0.3), Inches(0.05), W - Inches(0.6), HDR_H - Inches(0.1))
    tf  = txb.text_frame
    tf.word_wrap = False
    p   = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    run = p.add_run()
    run.text = title_text
    run.font.size  = Pt(16)
    run.font.bold  = True
    run.font.color.rgb = WHITE
    run.font.name  = "Calibri"


def add_footer(slide, slide_num, total=10):
    """Full-width navy footer bar."""
    top = H - FTR_H
    bar = add_rect(slide, 0, top, W, FTR_H, fill_color=NAVY)
    bar.name = "FooterBar"
    # Left text
    txb_l = slide.shapes.add_textbox(Inches(0.2), top + Inches(0.04),
                                      Inches(7), FTR_H - Inches(0.08))
    tf = txb_l.text_frame
    p  = tf.paragraphs[0]
    run = p.add_run()
    run.text = "U-HAP: Unified Authorization over Heterogeneous Policies"
    run.font.size  = Pt(7)
    run.font.color.rgb = WHITE
    run.font.name  = "Calibri"
    # Right text
    txb_r = slide.shapes.add_textbox(W - Inches(1.2), top + Inches(0.04),
                                      Inches(1.0), FTR_H - Inches(0.08))
    tf = txb_r.text_frame
    p  = tf.paragraphs[0]
    p.alignment = PP_ALIGN.RIGHT
    run = p.add_run()
    run.text = f"{slide_num}/{total}"
    run.font.size  = Pt(7)
    run.font.color.rgb = WHITE
    run.font.name  = "Calibri"


# ════════════════════════════════════════════════════════════════════════════
# CALLOUT BOX
# ════════════════════════════════════════════════════════════════════════════

def callout_box(slide, left, top, width, height, title, bullets,
                title_font_pt=9, body_font_pt=7,
                title_bg=NAVY, title_fg=WHITE, body_bg=GRAY):
    """
    Draws a callout box:
    1. Outer border rect (navy 0.5pt line, body_bg fill)
    2. Title bar (solid title_bg, title text in title_fg, bold)
    3. Body: bullet paragraphs below title bar
    """
    TITLE_H = Inches(0.26)
    PAD_L   = Inches(0.1)
    PAD_T   = Inches(0.04)

    # Outer box
    outer = add_rect(slide, left, top, width, height,
                     fill_color=body_bg, line_color=NAVY, line_pt=0.5)

    # Title bar
    title_bar = add_rect(slide, left, top, width, TITLE_H,
                         fill_color=title_bg)

    # Title text
    ttxb = slide.shapes.add_textbox(left + PAD_L, top + Pt(2),
                                     width - PAD_L * 2, TITLE_H - Pt(4))
    tf = ttxb.text_frame
    tf.word_wrap = True
    p  = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    run = p.add_run()
    run.text = title
    run.font.size  = Pt(title_font_pt)
    run.font.bold  = True
    run.font.color.rgb = title_fg
    run.font.name  = "Calibri"

    # Body text box
    body_top = top + TITLE_H + PAD_T
    body_h   = height - TITLE_H - PAD_T * 2
    btxb = slide.shapes.add_textbox(left + PAD_L, body_top,
                                     width - PAD_L * 2, body_h)
    tf = btxb.text_frame
    tf.word_wrap = True

    first = True
    for bullet in bullets:
        if first:
            p = tf.paragraphs[0]
            first = False
        else:
            p = tf.add_paragraph()
        p.alignment = PP_ALIGN.LEFT
        # Bullet char in TEAL
        run_b = p.add_run()
        run_b.text = "• "
        run_b.font.size  = Pt(body_font_pt)
        run_b.font.color.rgb = TEAL
        run_b.font.name  = "Calibri"
        # Bullet text in NAVY_D
        run_t = p.add_run()
        run_t.text = bullet
        run_t.font.size  = Pt(body_font_pt)
        run_t.font.color.rgb = NAVY_D
        run_t.font.name  = "Calibri"

    return outer, title_bar


def callout_body_text(slide, left, top, width, height, title, body_text,
                      title_font_pt=9, body_font_pt=7,
                      title_bg=NAVY, title_fg=WHITE, body_bg=GRAY):
    """Callout with a single prose body text (no bullet prefix)."""
    TITLE_H = Inches(0.26)
    PAD_L   = Inches(0.1)
    PAD_T   = Inches(0.04)

    add_rect(slide, left, top, width, height,
             fill_color=body_bg, line_color=NAVY, line_pt=0.5)
    add_rect(slide, left, top, width, TITLE_H, fill_color=title_bg)

    ttxb = slide.shapes.add_textbox(left + PAD_L, top + Pt(2),
                                     width - PAD_L * 2, TITLE_H - Pt(4))
    tf = ttxb.text_frame
    tf.word_wrap = True
    p  = tf.paragraphs[0]
    run = p.add_run()
    run.text = title
    run.font.size  = Pt(title_font_pt)
    run.font.bold  = True
    run.font.color.rgb = title_fg
    run.font.name  = "Calibri"

    body_top = top + TITLE_H + PAD_T
    body_h   = height - TITLE_H - PAD_T * 2
    btxb = slide.shapes.add_textbox(left + PAD_L, body_top,
                                     width - PAD_L * 2, body_h)
    tf = btxb.text_frame
    tf.word_wrap = True
    p  = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    run = p.add_run()
    run.text = body_text
    run.font.size  = Pt(body_font_pt)
    run.font.color.rgb = NAVY_D
    run.font.name  = "Calibri"


def callout_mixed(slide, left, top, width, height, title, body_text, bullets,
                  title_font_pt=9, body_font_pt=7,
                  title_bg=NAVY, title_fg=WHITE, body_bg=GRAY):
    """Callout with prose intro then bullets."""
    TITLE_H = Inches(0.26)
    PAD_L   = Inches(0.1)
    PAD_T   = Inches(0.04)

    add_rect(slide, left, top, width, height,
             fill_color=body_bg, line_color=NAVY, line_pt=0.5)
    add_rect(slide, left, top, width, TITLE_H, fill_color=title_bg)

    ttxb = slide.shapes.add_textbox(left + PAD_L, top + Pt(2),
                                     width - PAD_L * 2, TITLE_H - Pt(4))
    tf = ttxb.text_frame
    tf.word_wrap = True
    p  = tf.paragraphs[0]
    run = p.add_run()
    run.text = title
    run.font.size  = Pt(title_font_pt)
    run.font.bold  = True
    run.font.color.rgb = title_fg
    run.font.name  = "Calibri"

    body_top = top + TITLE_H + PAD_T
    body_h   = height - TITLE_H - PAD_T * 2
    btxb = slide.shapes.add_textbox(left + PAD_L, body_top,
                                     width - PAD_L * 2, body_h)
    tf = btxb.text_frame
    tf.word_wrap = True
    p  = tf.paragraphs[0]
    run = p.add_run()
    run.text = body_text
    run.font.size  = Pt(body_font_pt)
    run.font.color.rgb = NAVY_D
    run.font.name  = "Calibri"

    for bullet in bullets:
        p = tf.add_paragraph()
        run_b = p.add_run()
        run_b.text = "• "
        run_b.font.size  = Pt(body_font_pt)
        run_b.font.color.rgb = TEAL
        run_b.font.name  = "Calibri"
        run_t = p.add_run()
        run_t.text = bullet
        run_t.font.size  = Pt(body_font_pt)
        run_t.font.color.rgb = NAVY_D
        run_t.font.name  = "Calibri"


# ════════════════════════════════════════════════════════════════════════════
# TABLE HELPER
# ════════════════════════════════════════════════════════════════════════════

def _set_cell_bg(cell, rgb: RGBColor):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    solidFill = etree.SubElement(tcPr, qn('a:solidFill'))
    srgbClr   = etree.SubElement(solidFill, qn('a:srgbClr'))
    srgbClr.set('val', _rgb_hex(rgb))


def _set_cell_border(cell, rgb: RGBColor, pt=0.5):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    hex_c = _rgb_hex(rgb)
    w_val = int(pt * 12700)  # EMUs per point
    for side in ('a:lnL', 'a:lnR', 'a:lnT', 'a:lnB'):
        ln = etree.SubElement(tcPr, qn(side))
        ln.set('w', str(w_val))
        ln.set('cap', 'flat')
        solidFill = etree.SubElement(ln, qn('a:solidFill'))
        srgbClr   = etree.SubElement(solidFill, qn('a:srgbClr'))
        srgbClr.set('val', hex_c)


def add_table(slide, left, top, width, col_widths, rows,
              header_bg=NAVY, header_fg=WHITE, font_pt=7):
    """
    Create a real PPTX table.
    rows = list of lists of strings (first row = header).
    col_widths = list of Inches() values (must sum ≈ width).
    """
    n_rows = len(rows)
    n_cols = len(col_widths)

    # Compute height: 0.22 in per row
    row_h    = Inches(0.22)
    tbl_h    = row_h * n_rows
    tbl_shape = slide.shapes.add_table(n_rows, n_cols, left, top, width, tbl_h)
    tbl = tbl_shape.table

    # Set column widths
    for ci, cw in enumerate(col_widths):
        tbl.columns[ci].width = cw

    # Set row heights
    for ri in range(n_rows):
        tbl.rows[ri].height = row_h

    for ri, row_data in enumerate(rows):
        is_header = (ri == 0)
        is_alt    = (ri % 2 == 0) and not is_header
        bg = header_bg if is_header else (GRAY if is_alt else WHITE)
        fg = header_fg if is_header else NAVY_D

        for ci, cell_text in enumerate(row_data):
            cell = tbl.cell(ri, ci)
            # Handle tuple: (text, color)
            if isinstance(cell_text, tuple):
                text, text_color = cell_text
            else:
                text       = cell_text
                text_color = fg

            # Background
            _set_cell_bg(cell, bg)
            # Border
            _set_cell_border(cell, NAVY, 0.5)

            # Text
            tf = cell.text_frame
            tf.word_wrap = True
            p  = tf.paragraphs[0]
            p.alignment = PP_ALIGN.CENTER
            run = p.add_run()
            run.text = str(text)
            run.font.size  = Pt(font_pt)
            run.font.bold  = is_header
            run.font.color.rgb = text_color
            run.font.name  = "Calibri"

    return tbl_shape


# ════════════════════════════════════════════════════════════════════════════
# HIGHLIGHT BANNER
# ════════════════════════════════════════════════════════════════════════════

def add_highlight_banner(slide, left, top, width, text, font_pt=7):
    """Teal left-border box: GRAY bg + 3pt TEAL left strip + NAVY_D text."""
    H_BAN  = Inches(0.32)
    STRIP_W = Inches(0.04)

    # Gray background
    add_rect(slide, left, top, width, H_BAN, fill_color=GRAY)
    # Teal left strip
    add_rect(slide, left, top, STRIP_W, H_BAN, fill_color=TEAL)
    # Text
    add_textbox(slide, left + STRIP_W + Inches(0.06), top + Inches(0.04),
                width - STRIP_W - Inches(0.1), H_BAN - Inches(0.08),
                text, font_pt=font_pt, color=NAVY_D, italic=True)


# ════════════════════════════════════════════════════════════════════════════
# SLIDE BUILDERS
# ════════════════════════════════════════════════════════════════════════════

def build_slide_01(prs):
    """Title slide — full navy background, no header/footer."""
    layout = prs.slide_layouts[6]  # blank
    sl = prs.slides.add_slide(layout)

    # Full navy bg
    add_rect(sl, 0, 0, W, H, fill_color=NAVY)

    # Top/bottom teal stripes
    add_rect(sl, 0, 0, W, Inches(0.08), fill_color=TEAL)
    add_rect(sl, 0, H - Inches(0.08), W, Inches(0.08), fill_color=TEAL)

    cy = Inches(0.9)
    # Title
    txb = sl.shapes.add_textbox(Inches(0.5), cy, W - Inches(1.0), Inches(1.2))
    tf  = txb.text_frame
    tf.word_wrap = True
    p   = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    run = p.add_run()
    run.text = ("U-HAP: Unified Heterogeneous Authorization Protocol\n"
                "with Efficient Multi-Resource Verification in Kubernetes")
    run.font.size  = Pt(24)
    run.font.bold  = True
    run.font.color.rgb = WHITE
    run.font.name  = "Calibri"

    cy += Inches(1.4)
    txb2 = sl.shapes.add_textbox(Inches(0.5), cy, W - Inches(1.0), Inches(0.4))
    tf2  = txb2.text_frame
    p2   = tf2.paragraphs[0]
    p2.alignment = PP_ALIGN.CENTER
    r2 = p2.add_run()
    r2.text = "JCSSE 2026 · Conference Paper Presentation"
    r2.font.size  = Pt(12)
    r2.font.color.rgb = TEAL
    r2.font.name  = "Calibri"

    cy += Inches(0.55)
    for txt, pt in [
        ("Krittapak Jairak   Singha Junchan   Phisitphon Pruksorranan", 10),
        ("Advisor: Asst. Prof. Dr. Somchart Fugkeaw", 9),
        ("School of ICT, SIIT, Thammasat University, Thailand", 9),
    ]:
        txb3 = sl.shapes.add_textbox(Inches(0.5), cy, W - Inches(1.0), Inches(0.35))
        tf3  = txb3.text_frame
        p3   = tf3.paragraphs[0]
        p3.alignment = PP_ALIGN.CENTER
        r3 = p3.add_run()
        r3.text = txt
        r3.font.size  = Pt(pt)
        r3.font.color.rgb = WHITE
        r3.font.name  = "Calibri"
        cy += Inches(0.38)


def build_slide_background(prs):
    """Slide 2 — Background: SSO and Access Control in Kubernetes."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Background: SSO and Access Control in Kubernetes")
    add_footer(sl, 1, 13)

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left column
    callout_mixed(sl, lx, ct, lw, Inches(1.3),
                  "Access Control in Kubernetes",
                  "Post-authentication, every API call is dispatched as a SubjectAccessReview (SAR) to an authorization phase.",
                  [
                      "Built-in modes: RBAC (default), ABAC, Node, Webhook",
                      "Webhook authorizer delegates to an external service — where U-HAP plugs in",
                      "Native RBAC lacks fine-grained, context-aware authorization",
                  ],
                  title_font_pt=9, body_font_pt=8)

    tbl_rows = [
        ["Model", "How it grants access"],
        ["RBAC",  "Assign roles to users"],
        ["ABAC",  "Attribute conditions on request"],
        ["ACL",   "Explicit named list of users / groups"],
        ["Deny",  "Explicit block — overrides any allow"],
    ]
    add_table(sl, lx, ct + Inches(1.37), lw,
              [Inches(0.75), Inches(3.7)], tbl_rows, font_pt=8)

    # Right column
    callout_mixed(sl, rx, ct, rw, Inches(1.3),
                  "Single Sign-On (SSO)",
                  "SSO lets a user authenticate once (e.g. via OIDC / Keycloak) and reuse that identity across services.",
                  [
                      "Solves authentication — who you are",
                      "Does NOT solve authorization — what you may do",
                      "After SSO, each resource still enforces its own policy model independently",
                  ],
                  title_font_pt=9, body_font_pt=8)

    add_highlight_banner(sl, rx, ct + Inches(1.37), rw,
                         "SSO unifies login; it leaves authorization fragmented across RBAC, ABAC, and ACL. "
                         "U-HAP unifies the authorization side.")

    # Simple diagram below banner
    diag_t = ct + Inches(1.78)
    add_textbox(sl, rx, diag_t, rw, Inches(0.22),
                "User  →  SSO (authn ✓)  →  RBAC? / ABAC? / ACL?",
                font_pt=8, color=NAVY_D, italic=True, align=PP_ALIGN.CENTER)
    add_textbox(sl, rx, diag_t + Inches(0.24), rw, Inches(0.22),
                "authorization still per-resource  ← problem",
                font_pt=7, color=RED, italic=True, align=PP_ALIGN.CENTER)


def build_slide_related_work(prs):
    """Slide 3 — Related Work and Its Limitations."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Related Work and Its Limitations")
    add_footer(sl, 2, 13)

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left column
    callout_mixed(sl, lx, ct, lw, Inches(1.1),
                  "Hardening & Misconfiguration [1–3, 9–11]",
                  "NSA/CISA guidance; empirical misconfig studies; EPScan; formal verification.",
                  [
                      "Limitation: target correctness of individual policies — not unified authorization across mixed models",
                  ],
                  title_font_pt=9, body_font_pt=8)

    callout_mixed(sl, lx, ct + Inches(1.17), lw, Inches(1.1),
                  "RBAC, Policy-as-Code & Zero Trust [4, 12–14]",
                  "K8s RBAC; Zero Trust architecture; PerfSPEC; compile-time optimization.",
                  [
                      "Limitation: operate within a single model — repeated per-layer evaluation adds redundant checks and latency",
                  ],
                  title_font_pt=9, body_font_pt=8)

    # Right column
    callout_mixed(sl, rx, ct, rw, Inches(1.4),
                  "Expressive & Graph-Based Models [7, 8, 15–18]",
                  "XACML (expressive but heavyweight PDP); Zanzibar (scales globally but needs runtime graph traversal); ABAC-to-RBAC conversion.",
                  [
                      "Limitation: heavy PDPs, runtime-traversal overhead, or interoperability only — no efficient unified runtime",
                  ],
                  title_font_pt=9, body_font_pt=8)

    callout_body_text(sl, rx, ct + Inches(1.47), rw, Inches(0.85),
                      "The Gap U-HAP Fills",
                      "No prior work offers a unified framework spanning RBAC + ABAC + ACL + deny "
                      "that minimizes redundant evaluation while guaranteeing scalable, low-latency "
                      "multi-resource authorization.",
                      title_font_pt=9, body_font_pt=8,
                      title_bg=TEAL)


def build_slide_02(prs):
    """Slide 2 — Motivation."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Motivation: The Kubernetes Authorization Problem")
    add_footer(sl, 3, 13)

    # ── Left column ────────────────────────────────────────────────────────
    lx = LMARGIN
    lw = Inches(4.2)
    ct = CONTENT_T

    add_textbox(sl, lx, ct, lw, Inches(0.28),
                "Modern K8s deployments are multi-model",
                font_pt=11, bold=True, color=NAVY)

    # Simple diagram with boxes and arrows (text-based)
    diag_t = ct + Inches(0.32)
    # Top box: User Request
    add_rect(sl, lx + Inches(1.2), diag_t, Inches(1.8), Inches(0.28),
             fill_color=WHITE, line_color=TEAL, line_pt=1.0)
    add_textbox(sl, lx + Inches(1.2), diag_t + Inches(0.04), Inches(1.8), Inches(0.22),
                "User Request", font_pt=8, bold=True, color=TEAL, align=PP_ALIGN.CENTER)

    # Arrow down
    arr_top = diag_t + Inches(0.28)
    add_textbox(sl, lx + Inches(2.0), arr_top, Inches(0.3), Inches(0.2),
                "↓", font_pt=10, color=GRAY_D, align=PP_ALIGN.CENTER)

    # Three boxes
    box_t = arr_top + Inches(0.22)
    box_labels = ["Namespace A\nRBAC", "Namespace B\nABAC", "Namespace C\nACL"]
    box_x = lx
    bw = Inches(1.3)
    for lbl in box_labels:
        add_rect(sl, box_x, box_t, bw, Inches(0.38),
                 fill_color=GRAY, line_color=GRAY_D, line_pt=0.5)
        add_textbox(sl, box_x + Inches(0.05), box_t + Inches(0.04),
                    bw - Inches(0.1), Inches(0.30), lbl,
                    font_pt=7, color=NAVY_D, align=PP_ALIGN.CENTER)
        box_x += bw + Inches(0.15)

    # Italic red note
    note_t = box_t + Inches(0.44)
    add_textbox(sl, lx, note_t, lw, Inches(0.22),
                "Separate checks, incompatible semantics",
                font_pt=7, italic=True, color=RED)

    # Small table
    tbl_t = note_t + Inches(0.28)
    tbl_rows = [
        ["Model", "Description"],
        ["RBAC", "Role-Based: grant access by assigning roles to users"],
        ["ABAC", "Attribute-Based: grant access via attribute conditions"],
        ["ACL",  "Access Control List: explicit named list of allowed users"],
    ]
    add_table(sl, lx, tbl_t, lw,
              [Inches(0.6), Inches(3.55)],
              tbl_rows, font_pt=7)

    # ── Right column ───────────────────────────────────────────────────────
    rx = Inches(4.72)
    rw = Inches(5.0)
    callout_top = ct

    callout_box(sl, rx, callout_top, rw, Inches(1.75),
                "Three Key Challenges",
                [
                    "Semantic fragmentation — RBAC, ABAC, ACL use incompatible rule languages and evaluation semantics",
                    "Non-deterministic conflicts — Implicit ordering across models yields inconsistent deny/allow decisions",
                    "Runtime inefficiency — Repeated policy scans evaluate irrelevant rules for every request",
                ],
                title_font_pt=11, body_font_pt=9)

    ban_t = callout_top + Inches(1.82)
    add_highlight_banner(sl, rx, ban_t, rw,
                         "Even with SSO handling authentication, authorization across multiple resources "
                         "remains fragmented, slow, and inconsistent.")


def build_slide_03(prs):
    """Slide 3 — Our Solution: U-HAP."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Our Solution: U-HAP")
    add_footer(sl, 4, 13)

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left column
    callout_body_text(sl, lx, ct, lw, Inches(0.98),
                      "Core Idea",
                      "Shift expensive reasoning offline. Compile all policy models into resource–action "
                      "indexed artifacts C(n,r,a). Every request-time authorization reduces to an O(1) index "
                      "lookup followed by cheap, model-specific index evaluation.",
                      title_font_pt=9, body_font_pt=8)

    callout_box(sl, lx, ct + Inches(1.05), lw, Inches(1.4),
                "Three-Phase Architecture",
                [
                    "Phase 1: Setup & trust configuration (deploy-time)",
                    "Phase 2: Compilation: DSL parse → DAG → indexed artifacts (policy-change time)",
                    "Phase 3: Request eval: O(1) lookup → pruning → index eval (every SAR — SubjectAccessReview)",
                ],
                body_font_pt=8)

    # Right column
    callout_box(sl, rx, ct, rw, Inches(2.5),
                "Key Contributions",
                [
                    "Universal semantic graph capturing RBAC, ABAC, and ACL in a unified DAG with deny-override semantics",
                    "Hash consing: structurally identical predicates share one node — 11 nodes reduced to 8 in the 4-policy example",
                    "Two-level pruning: policy-type pruning skips inactive model classes; token-driven pruning limits evaluation to relevant rules",
                    "Deterministic conflict resolution: deny-overrides-all, always, across all models",
                ],
                body_font_pt=8)


def build_slide_04(prs):
    """Slide 4 — System Architecture."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "System Architecture: Three-Phase Design")
    add_footer(sl, 5, 13)

    lx = LMARGIN
    lw = Inches(5.9)
    rx = Inches(6.4)
    rw = Inches(3.3)
    ct = CONTENT_T

    # Architecture figure
    add_picture_safe(sl, FIG / "system_architecture.png",
                     lx, ct, Inches(4.3))

    # Right callouts
    callout_box(sl, rx, ct, rw, Inches(0.82),
                "Phase 1: Setup (deploy-time)",
                ["Load & validate DSL policies",
                 "Init webhook; zero request-time cost"],
                body_font_pt=7)

    callout_box(sl, rx, ct + Inches(0.88), rw, Inches(1.0),
                "Phase 2: Compilation (per policy change)",
                ["Parse DSL → hash-consed DAG",
                 "Compile C(n,r,a) indices per triple",
                 "Store artifacts in registry"],
                body_font_pt=7)

    callout_box(sl, rx, ct + Inches(1.95), rw, Inches(1.2),
                "Phase 3: Request-time (every SAR)",
                ["O(1) lookup on (n,r,a)",
                 "Two-level pruning skips inactive models",
                 "Eval: hash set / bit-vector / gates",
                 "Return ALLOW/DENY + audit log"],
                body_font_pt=7)


def _crop_slide05_image():
    """Crop left half of slide-05.png for hash consing diagram."""
    src = PNG / "slide-05.png"
    if not src.exists():
        WARNINGS.append(f"Missing: {src}")
        return None
    img = PILImage.open(src)
    w, h = img.size
    # Crop: skip ~60px top (header), ~40px bottom (footer), left half
    cropped = img.crop((0, 60, w // 2, h - 40))
    cropped.save(str(TMP))
    return TMP


def build_slide_05(prs):
    """Slide 5 — Hash Consing."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Compilation: Hash Consing and Indexed Artifacts")
    add_footer(sl, 6, 13)

    lx = LMARGIN
    lw = Inches(4.4)
    rx = Inches(4.9)
    rw = Inches(4.8)
    ct = CONTENT_T

    # Cropped hash consing diagram
    crop_path = _crop_slide05_image()
    if crop_path:
        add_picture_safe(sl, crop_path, lx, ct, Inches(4.2))
    else:
        add_textbox(sl, lx, ct, lw, Inches(1.0),
                    "[Hash Consing TikZ diagram — see slide-05.png]",
                    font_pt=8, color=GRAY_D, italic=True)

    # Right column
    callout_box(sl, rx, ct, rw, Inches(1.5),
                "What Hash Consing Gives You",
                [
                    "Identical sub-expressions across policies share one DAG node",
                    "Each node evaluated at most once per request (memoized)",
                    "Structural equality check — not string comparison",
                    "Cost grows sub-linearly as policies share predicates",
                ],
                body_font_pt=7)

    # Sub-table inside callout area
    tbl_t = ct + Inches(1.57)
    tbl_rows = [
        ["Index", "Description"],
        ["I_deny", "deny candidate set (token-pruned hash set)"],
        ["I_acl",  "ACL user/group hash set (O(1) membership)"],
        ["b_rbac", "RBAC bit-vector (one AND with b_user)"],
        ["I_abac", "ABAC gate list, cost-sorted, key-pruned"],
    ]
    callout_body_text(sl, rx, tbl_t, rw, Inches(0.26),
                      "Compiled Indexed Artifacts C(n,r,a)",
                      "", title_font_pt=8, body_font_pt=7)
    add_table(sl, rx, tbl_t + Inches(0.28), rw,
              [Inches(0.8), Inches(3.95)],
              tbl_rows, font_pt=7)

    ord_t = tbl_t + Inches(0.28) + Inches(0.22 * 5) + Inches(0.08)
    add_textbox(sl, rx, ord_t, rw, Inches(0.22),
                "Runtime order: Cache → Deny → ACL → RBAC → ABAC → Default Deny",
                font_pt=7, color=NAVY_D, italic=True)

    ban_t = ord_t + Inches(0.28)
    add_highlight_banner(sl, rx, ban_t, rw,
                         "The DAG is a compile-time artifact only. "
                         "No graph traversal at runtime — pure index lookup.")


def build_slide_06(prs):
    """Slide 6 — Two-Level Pruning Strategy."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Two-Level Pruning Strategy")
    add_footer(sl, 7, 13)

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left
    callout_mixed(sl, lx, ct, lw, Inches(1.35),
                  "Level 1 — Policy-Type Pruning",
                  "Skip entire model classes that cannot produce a decision for this request.",
                  [
                      "If no deny rules exist for (n,r,a): skip deny phase",
                      "If no RBAC policies apply: skip bit-vector AND",
                      "If caller has no attributes: skip ABAC gate list",
                  ],
                  body_font_pt=8)

    callout_mixed(sl, lx, ct + Inches(1.42), lw, Inches(1.38),
                  "Level 2 — Token-Driven Pruning",
                  "Restrict evaluation to rules matching the caller's token.",
                  [
                      "Hash the request token; filter I_deny and I_abac to matching entries only",
                      "Pruning happens before evaluation — zero cost for non-matching rules",
                      "Compound benefit: both levels apply independently",
                  ],
                  body_font_pt=8)

    # Right
    callout_body_text(sl, rx, ct, rw, Inches(1.1),
                      "Deny-Overrides-All Invariant",
                      "Any deny match terminates evaluation immediately and returns DENY — "
                      "regardless of any allow rules in RBAC, ABAC, or ACL. "
                      "This invariant is checked first, always.",
                      body_font_pt=8)

    callout_box(sl, rx, ct + Inches(1.17), rw, Inches(1.3),
                "Result: O(1) Effective Complexity",
                [
                    "Cache hit: 1 hash lookup",
                    "ACL: 1 hash-set membership check",
                    "RBAC: 1 bitwise AND",
                    "ABAC: pruned gate list, cost-sorted, memoized",
                    "No policy scan. No BFS. No interpreter overhead.",
                ],
                body_font_pt=8)


def build_slide_07(prs):
    """Slide 9 — Evaluation Setup."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Evaluation Setup")
    add_footer(sl, 8, 13)

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left column
    callout_box(sl, lx, ct, lw, Inches(1.1),
                "Hardware and Implementation",
                [
                    "AMD Ryzen 9 7945HX (16C/32T), 32 GB DDR5-4800, CachyOS Linux",
                    "U-HAP: Python 3.11 (in-memory evaluation)",
                    "Baseline: conventional SSO-based system — sequential policy scanning",
                ],
                body_font_pt=8)

    callout_box(sl, lx, ct + Inches(1.17), lw, Inches(1.4),
                "Measurement Methodology",
                [
                    "Median of 1,000 iterations after 50 warm-up runs",
                    "In-memory policy lookup only — no network, no auth overhead",
                    "Each namespace: 46 rules (10 RBAC, 20 ABAC, 10 ACL, 1 deny, 5 hierarchy edges)",
                    "ABAC gates: AND/OR/ATLEAST with ~50% atom sharing across rules",
                ],
                body_font_pt=8)

    # Right column
    callout_box(sl, rx, ct, rw, Inches(1.0),
                "Why In-Memory Benchmarks?",
                [
                    "Isolates pure algorithm cost from network and framework overhead",
                    "Reveals true compilation gains: hash-consed DAG vs. sequential scan",
                    "Caching effect visible directly without HTTP round-trip noise",
                ],
                body_font_pt=8)

    callout_box(sl, rx, ct + Inches(1.07), rw, Inches(1.0),
                "Baseline: SSO-Based Sequential Evaluation",
                [
                    "Iterates over all policy rules per request",
                    "RBAC: repeated role resolution + hierarchy traversal at runtime",
                    "Represents conventional authorization without compile-time indexing",
                ],
                body_font_pt=8)


def build_slide_08(prs):
    """Slide 8 — Experiment 1: Policy Verification Efficiency."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Experiment 1: Policy Verification Efficiency")
    add_footer(sl, 9, 13)

    lx = LMARGIN
    lw = Inches(5.3)
    rx = Inches(5.8)
    rw = Inches(3.9)
    ct = CONTENT_T

    # Figure
    add_picture_safe(sl, FIG / "fig2_namespace_isolation.png",
                     lx, ct, Inches(2.8))

    # Key results callout
    callout_box(sl, lx, ct + Inches(2.88), lw, Inches(1.15),
                "Key Results",
                [
                    "Isolation: curves flat as N:10→1,000 — adding namespaces has zero cost",
                    "U-HAP: ≈15.5 μs — O(1) lookup, constant vs. N",
                    "+Cache: ≈1.8 μs — 14–15× speedup over SSO",
                    "SSO: ≈26 μs — 1.6–1.7× slower than U-HAP",
                ],
                body_font_pt=9)

    # Right column
    add_textbox(sl, rx, ct, rw, Inches(0.25),
                "Latency (μs, median, 1,000 iters)",
                font_pt=8, bold=True, color=NAVY_D)
    add_textbox(sl, rx, ct + Inches(0.28), rw, Inches(0.22),
                "46 rules each: 10 RBAC + 20 ABAC + 10 ACL + 1 deny",
                font_pt=7, color=GRAY_D)

    tbl_rows = [
        ["N", "U-HAP", "+Cache", "SSO"],
        ["10",   "15.6", "1.7", "26.9"],
        ["50",   "15.4", "1.8", "26.0"],
        ["100",  "15.5", "1.8", "25.8"],
        ["200",  "15.6", "1.7", "25.2"],
        ["300",  "15.4", "1.8", "26.4"],
        ["500",  "15.6", "1.8", "26.0"],
        ["750",  "15.7", "1.7", "25.4"],
        ["1000", "15.4", "1.8", "25.3"],
    ]
    add_table(sl, rx, ct + Inches(0.54), rw,
              [Inches(0.7), Inches(1.0), Inches(1.0), Inches(1.15)],
              tbl_rows, font_pt=7)


def build_slide_09(prs):
    """Slide 9 — Experiment 2: Policy Size Impact."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Experiment 2: Policy Size Impact")
    add_footer(sl, 10, 13)

    lx = LMARGIN
    lw = Inches(5.3)
    rx = Inches(5.8)
    rw = Inches(3.9)
    ct = CONTENT_T

    add_picture_safe(sl, FIG / "fig3_permodel_latency.png",
                     lx, ct, Inches(2.8))

    callout_box(sl, lx, ct + Inches(2.88), lw, Inches(1.15),
                "Key Results",
                [
                    "ABAC: hash-consed DAG → 16.9× at k=320; crossover k≈18",
                    "RBAC: bit-vector AND → 5.6× at k=320; crossover k≈15",
                    "ACL: hash-set → 5.0× at k=320; crossover k≈35",
                    "<1× at small k: compilation overhead not yet amortized",
                ],
                body_font_pt=9)

    add_textbox(sl, rx, ct, rw, Inches(0.25),
                "Speedup vs. SSO baseline",
                font_pt=8, bold=True, color=NAVY_D)
    add_textbox(sl, rx, ct + Inches(0.28), rw, Inches(0.22),
                "<1× = compilation cost not yet amortized",
                font_pt=7, color=GRAY_D)

    tbl_rows = [
        ["k", "ABAC", "RBAC", "ACL"],
        ["5",   "0.66×", "0.96×", "0.54×"],
        ["10",  "0.92×", "0.80×", "0.66×"],
        ["20",  "1.64×", "1.01×", "0.85×"],
        ["40",  "3.44×", "1.25×", "1.27×"],
        ["80",  "6.00×", "1.83×", "2.05×"],
        ["160", "9.83×", "3.20×", "3.58×"],
        ["320", "16.9×", "5.6×",  "5.0×"],
    ]
    tbl_shape = add_table(sl, rx, ct + Inches(0.54), rw,
              [Inches(0.55), Inches(1.1), Inches(1.1), Inches(1.1)],
              tbl_rows, font_pt=7)

    # Bold last data row (k=320)
    tbl = tbl_shape.table
    for ci in range(4):
        cell = tbl.cell(7, ci)
        for para in cell.text_frame.paragraphs:
            for run in para.runs:
                run.font.bold = True


def build_slide_10(prs):
    """Slide 10 — Experiment 3: Policy Update Latency vs. OPA."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Experiment 3: Policy Update Latency vs. OPA")
    add_footer(sl, 11, 13)

    lx = LMARGIN
    lw = Inches(5.3)
    rx = Inches(5.8)
    rw = Inches(3.9)
    ct = CONTENT_T

    add_picture_safe(sl, FIG / "fig5_update_latency.png",
                     lx, ct, Inches(2.8))

    callout_box(sl, lx, ct + Inches(2.88), lw, Inches(1.15),
                "Key Results",
                [
                    "2.73× faster total update at n=2,000 (223 ms vs. 611 ms)",
                    "19.5× faster post-parse engine path at n=2,000",
                    "U-HAP grows linearly; OPA grows super-linearly",
                    "100/100 decisions verified identical (equivalence gate)",
                ],
                body_font_pt=9)

    add_textbox(sl, rx, ct, rw, Inches(0.25),
                "Edit-to-first-decision latency (ms)",
                font_pt=8, bold=True, color=NAVY_D)

    tbl_rows = [
        ["n", "U-HAP\nTotal", "OPA\nTotal", "×", "U-HAP\nPost-parse", "OPA\nPost-parse"],
        ["10",   "1.75",   "2.85",   "1.63×", "0.14",  "2.85"],
        ["100",  "14.76",  "26.60",  "1.80×", "2.03",  "26.60"],
        ["500",  "57.35",  "119.40", "2.08×", "7.87",  "119.40"],
        ["1000", "109.99", "277.32", "2.52×", "16.27", "277.32"],
        ["2000", "223.41", "610.54", "2.73×", "31.31", "610.54"],
    ]
    tbl_shape = add_table(sl, rx, ct + Inches(0.30), rw,
              [Inches(0.5), Inches(0.6), Inches(0.6), Inches(0.5), Inches(0.85), Inches(0.8)],
              tbl_rows, font_pt=6)

    # Bold last data row (n=2000)
    tbl = tbl_shape.table
    for ci in range(6):
        cell = tbl.cell(5, ci)
        for para in cell.text_frame.paragraphs:
            for run in para.runs:
                run.font.bold = True


def build_slide_11(prs):
    """Slide 11 — Conclusion."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "Conclusion")
    add_footer(sl, 12, 13)

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left
    callout_body_text(sl, lx, ct, lw, Inches(1.05),
                      "What We Built",
                      "U-HAP is a compilation-driven, index-based Kubernetes webhook authorizer "
                      "unifying RBAC, ABAC, and ACL under a single semantic DAG with deterministic "
                      "deny-override conflict resolution.",
                      title_font_pt=12, body_font_pt=9)

    callout_box(sl, lx, ct + Inches(1.12), lw, Inches(1.6),
                "Key Results",
                [
                    "Near-constant latency: ≈1.7× vs. SSO baseline; flat to N=1,000 namespaces",
                    "~14× caching speedup on repeated requests",
                    "16.9× ABAC speedup at k=320; RBAC 5.6×, ACL 5.0×",
                    "2.73× faster policy-update vs. OPA at n=2,000",
                    "19.5× faster post-parse path vs. OPA",
                ],
                body_font_pt=9)

    # Right
    callout_box(sl, rx, ct, rw, Inches(1.2),
                "Why It Works",
                [
                    "Compile, don’t scan — all complexity offline; runtime is index lookup + bitwise ops only",
                    "Share, don’t repeat — hash consing eliminates redundant sub-expression evaluation",
                    "Prune early, prune deep — two-level pruning skips entire model classes before eval",
                ],
                body_font_pt=9)

    callout_box(sl, rx, ct + Inches(1.27), rw, Inches(1.4),
                "Future Work",
                [
                    "Reimplement in Go/Rust to eliminate Python/Gunicorn HTTP overhead",
                    "Cross-namespace policy composition",
                    "Dynamic policy reload without restart",
                ],
                body_font_pt=9)


def build_slide_references(prs):
    """Slide 14 — References."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_header(sl, "References")
    add_footer(sl, 13, 13)

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T + Inches(0.05)
    line_h = Inches(0.195)

    refs_left = [
        "[1] NSA & CISA, \"Kubernetes Hardening Guidance,\" NSA Cybersec. Tech. Report, ver. 1.2, 2022.",
        "[2] A. Rahman et al., \"Security Misconfigurations in Open Source Kubernetes Manifests,\" ACM TOSEM, 32(4), 2023.",
        "[3] N. Yang et al., \"Take Over the Whole Cluster: Attacking Kubernetes via Excessive Permissions,\" ACM CCS, 2023.",
        "[4] G. Rostami, \"RBAC Authorization in Kubernetes,\" J. ICT Standardization, 11(3), 2023.",
        "[5] N. Farhadighalati et al., \"A Systematic Review of Access Control Models,\" IEEE Access, 13, 2025.",
        "[6] M. S. Rahaman et al., \"Access Control in Cloud-Native Architecture: A Mapping Study,\" Sensors, 23(7), 2023.",
        "[7] OASIS, \"XACML Version 3.0 Plus Errata 01,\" OASIS Standard, 2017.",
        "[8] M. Yang et al., \"A Graph-Based Framework for ABAC Policy Enforcement,\" DBSec, 2024.",
        "[9] Z. Moric et al., \"Security Hardening and Compliance Assessment of Kubernetes,\" J. Cybersec. Privacy, 5(2), 2025.",
    ]
    refs_right = [
        "[10] Y. Gu et al., \"EPScan: Automated Detection of Excessive RBAC Permissions,\" IEEE S&P, 2025.",
        "[11] A. Sissodiya et al., \"Formal Verification for Preventing Misconfigured Access Policies,\" IEEE Access, 13, 2025.",
        "[12] R. Chandramouli & Z. Butcher, \"A Zero Trust Architecture Model for Cloud-Native Apps,\" NIST SP 800-207A, 2023.",
        "[13] H. Nguyen et al., \"PerfSPEC: Profiling-Based Proactive Security Policy Enforcement,\" IEEE Computer, 2025.",
        "[14] S. Kern et al., \"Optimization of Access Control Policies,\" J. Inf. Secur. Appl., 70, 2022.",
        "[15] A. X. Liu et al., \"Designing Fast and Scalable XACML Policy Evaluation Engines,\" IEEE Trans. Computers, 60(12), 2011.",
        "[16] L. Ma et al., \"Authorization Model of Attribute Access Control Based on Knowledge Graph,\" UbiSec, 2024.",
        "[17] R. Pang et al., \"Zanzibar: Google's Consistent, Global Authorization System,\" USENIX ATC, 2019.",
        "[18] M. Davari & M. Zulkernine, \"Automatic Conversion of ABAC Policies for RBAC Systems,\" IEEE DSC, 2023.",
    ]

    for i, ref in enumerate(refs_left):
        add_textbox(sl, lx, ct + line_h * i, lw, line_h, ref, font_pt=6, color=NAVY_D)

    for i, ref in enumerate(refs_right):
        add_textbox(sl, rx, ct + line_h * i, rw, line_h, ref, font_pt=6, color=NAVY_D)


def build_slide_12(prs):
    """Slide 12 — Q&A (navy background, no header/footer)."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)

    add_rect(sl, 0, 0, W, H, fill_color=NAVY)
    add_rect(sl, 0, 0, W, Inches(0.08), fill_color=TEAL)
    add_rect(sl, 0, H - Inches(0.08), W, Inches(0.08), fill_color=TEAL)

    # "Thank you!"
    txb = sl.shapes.add_textbox(Inches(0.5), Inches(1.5), W - Inches(1.0), Inches(1.2))
    tf  = txb.text_frame
    p   = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    run = p.add_run()
    run.text = "Thank you!"
    run.font.size  = Pt(40)
    run.font.bold  = True
    run.font.color.rgb = WHITE
    run.font.name  = "Calibri"

    # Subtitle
    txb_sub = sl.shapes.add_textbox(Inches(0.5), Inches(2.5), W - Inches(1.0), Inches(0.5))
    tf_sub  = txb_sub.text_frame
    p_sub   = tf_sub.paragraphs[0]
    p_sub.alignment = PP_ALIGN.CENTER
    run_sub = p_sub.add_run()
    run_sub.text = "Questions are welcome."
    run_sub.font.size  = Pt(18)
    run_sub.font.color.rgb = TEAL
    run_sub.font.name  = "Calibri"

    # Contact
    txb2 = sl.shapes.add_textbox(Inches(0.5), Inches(3.0), W - Inches(1.0), Inches(0.8))
    tf2  = txb2.text_frame
    tf2.word_wrap = True
    for txt in ["Singha Junchan — 6622770350@g.siit.tu.ac.th",
                 "School of ICT, SIIT, Thammasat University"]:
        p2 = tf2.add_paragraph() if txt != "Singha Junchan — 6622770350@g.siit.tu.ac.th" else tf2.paragraphs[0]
        p2.alignment = PP_ALIGN.CENTER
        r2 = p2.add_run()
        r2.text = txt
        r2.font.size  = Pt(12)
        r2.font.color.rgb = TEAL
        r2.font.name  = "Calibri"


# ════════════════════════════════════════════════════════════════════════════
# BACKUP SLIDES (13–21)
# ════════════════════════════════════════════════════════════════════════════

def add_backup_header(sl, title):
    """Header with '(Backup)' appended."""
    add_header(sl, f"{title} (Backup)")


def build_slide_13(prs):
    """Backup: Runtime Evaluation Order."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "Runtime Evaluation Order (Phase 3)")

    lx = LMARGIN
    lw = Inches(5.0)
    rx = Inches(5.5)
    rw = Inches(4.2)
    ct = CONTENT_T

    # Numbered list callout
    steps = [
        "1. Cache hit? Return cached decision immediately",
        "2. Deny check: token-pruned candidates from I_deny; any match → DENY",
        "3. ACL: uid ∈ I_acl or groups ∩ I_acl ≠ ∅ (hash set, O(1))",
        "4. RBAC: b_user & b_rbac ≠ 0 (one bitwise AND)",
        "5. ABAC: attribute-key pruned → cost-sorted → hash-consed gate eval",
        "6. Default Deny: no rule matched → DENY",
    ]
    callout_box(sl, lx, ct, lw, Inches(2.2),
                "Evaluation Pipeline for each SAR",
                steps, body_font_pt=8)

    callout_box(sl, rx, ct, rw, Inches(2.2),
                "Correctness Invariants",
                [
                    "Deny-overrides-all checked first, always",
                    "DAG acyclicity verified at compile time",
                    "Resource-action isolation: eval of (n,r,a) touches only C(n,r,a)",
                    "Deterministic: same input → same output",
                    "Memoization: each DAG node evaluated at most once per request",
                    "Cache consistency: invalidated on any policy change",
                ],
                body_font_pt=8)


def build_slide_14(prs):
    """Backup: Correctness Scenarios S1–S7."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "Correctness Scenarios S1–S7")

    ct = CONTENT_T
    tbl_rows = [
        ["ID", "Subject", "Model", "Resource/Verb", "Context", "Expected"],
        ["S1", "alice",   "ABAC",      "pods/prod / get",    "on-premise + business-hours", ("ALLOW", GREEN)],
        ["S2", "alice",   "ABAC",      "pods/prod / get",    "remote",                      ("DENY",  RED  )],
        ["S3", "alice",   "RBAC",      "pods/dev / get",     "any",                         ("ALLOW", GREEN)],
        ["S4", "bob",     "ABAC",      "pods/prod / delete", "after-hours",                 ("DENY",  RED  )],
        ["S5", "*",       "Deny",      "secrets / delete",   "any",                         ("DENY",  RED  )],
        ["S6", "charlie", "ACL",       "pods/dev / get",     "any",                         ("ALLOW", GREEN)],
        ["S7", "dave",    "Hierarchy", "pods/prod / get",    "any",                         ("ALLOW", GREEN)],
    ]
    col_widths = [Inches(0.5), Inches(0.7), Inches(0.95), Inches(1.7), Inches(2.4), Inches(3.14)]
    add_table(sl, LMARGIN, ct, USABLE_W, col_widths, tbl_rows, font_pt=8)

    ban_t = ct + Inches(0.22 * 8) + Inches(0.15)
    add_highlight_banner(sl, LMARGIN, ban_t, USABLE_W,
                         "S7: dave is a Senior Developer. RBAC bit-vector encodes full transitive role "
                         "closure at compile time — no runtime BFS needed.")


def build_slide_15(prs):
    """Backup: Hash Consing — Worked Example (P1–P4)."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "Hash Consing — Worked Example (P1–P4)")

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    callout_body_text(sl, lx, ct, lw, Inches(1.8),
                      "Without Hash Consing (Naïve Tree)",
                      "Four policies P1–P4 share the predicate time.hour ∈ [9,18] and "
                      "location = ‘on-premise’, but each expands them independently. "
                      "Naïve tree: 11 nodes. The shared predicates are evaluated redundantly "
                      "for each policy, even within the same request.",
                      body_font_pt=8)

    callout_body_text(sl, rx, ct, rw, Inches(1.8),
                      "With Hash Consing (DAG)",
                      "Structural equality check at compile time identifies shared sub-expressions. "
                      "One canonical node per unique predicate. Hash-consed DAG: 8 nodes. "
                      "At request time, each node is evaluated at most once and its result memoized. "
                      "Policies referencing the same predicate re-use the cached result — "
                      "zero redundant computation.",
                      body_font_pt=8)

    ban_t = ct + Inches(1.87)
    add_highlight_banner(sl, LMARGIN, ban_t, USABLE_W,
                         "As policy sets grow and predicates are reused across rules, hash consing "
                         "provides sub-linear growth in both DAG size and evaluation cost.")


def build_slide_16(prs):
    """Backup: RBAC Bit-Vector Role Hierarchy."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "RBAC Bit-Vector Role Hierarchy")

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    callout_box(sl, lx, ct, lw, Inches(1.5),
                "Bit-Vector Construction (Compile Time)",
                [
                    "Enumerate all roles: assign each a unique bit position",
                    "For each role: compute transitive ancestors via BFS on role hierarchy",
                    "Set bits for all ancestors in that role’s bit-vector",
                    "Store in compiled registry — no BFS at runtime",
                ],
                body_font_pt=8)

    callout_box(sl, rx, ct, rw, Inches(1.5),
                "Runtime Evaluation",
                [
                    "b_user = bit-vector of all roles the requesting user holds (transitively)",
                    "b_rbac = bit-vector of roles allowed by the RBAC policy for (n,r,a)",
                    "Decision: b_user AND b_rbac ≠ 0 → ALLOW",
                    "One bitwise AND operation. O(1) regardless of role hierarchy depth.",
                ],
                body_font_pt=8)

    ban_t = ct + Inches(1.57)
    add_highlight_banner(sl, LMARGIN, ban_t, USABLE_W,
                         "For S7 (dave, Senior Developer): Senior Dev bit is set in b_rbac; "
                         "dave’s b_user includes Senior Dev bit → single AND returns ALLOW. No traversal.")


def build_slide_17(prs):
    """Backup: Memory Footprint."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "Memory Footprint")

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    callout_box(sl, lx, ct, lw, Inches(1.5),
                "Measured Footprint",
                [
                    "Total registry size: ≤ 2.7 MiB for N=1,000 namespaces, 46 rules each",
                    "Per-namespace: ≈2.7 KiB average",
                    "Hash consing reduces DAG size: 11 → 8 nodes in P1–P4 example",
                    "Bit-vectors: 1 word per role (64-bit CPU: up to 64 roles per word)",
                ],
                body_font_pt=8)

    callout_box(sl, rx, ct, rw, Inches(1.5),
                "Why It Stays Small",
                [
                    "Compiled indices are dense hash sets and bit-vectors — no redundant policy text",
                    "Hash consing eliminates duplicate predicate storage",
                    "Registry is keyed by (n,r,a) — only policies relevant to each triple are stored",
                ],
                body_font_pt=8)

    ban_t = ct + Inches(1.57)
    add_highlight_banner(sl, LMARGIN, ban_t, USABLE_W,
                         "≤ 2.7 MiB for the full N=1,000 test scenario — "
                         "well within typical container memory budgets.")


def build_slide_18(prs):
    """Backup: Cache Impact."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "Cache Impact")

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    callout_body_text(sl, lx, ct, lw, Inches(1.5),
                      "Measured Cache Impact",
                      "In-memory benchmark (1,000 iterations, 50 warm-ups): ≈14× speedup on repeated "
                      "requests — cache bypasses all evaluation, returning the stored decision in one "
                      "hash-table lookup. Benefit compounds at scale: Exp1 shows the 14× factor holds "
                      "across N=1,000 namespaces.",
                      body_font_pt=8)

    callout_box(sl, rx, ct, rw, Inches(1.5),
                "Cache Design",
                [
                    "Key: (namespace, resource, action, uid, groups-hash) → Decision",
                    "Invalidated on any policy change (write-through invalidation)",
                    "No stale decisions possible — consistency guaranteed",
                    "TTL not needed: policy changes are the only invalidation trigger",
                ],
                body_font_pt=8)

    ban_t = ct + Inches(1.57)
    add_highlight_banner(sl, LMARGIN, ban_t, USABLE_W,
                         "The 14× cache speedup means repeated authorization for the same "
                         "subject/resource pair is essentially free.")


def build_slide_19(prs):
    """Backup: Comparison with OPA."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "Comparison with OPA")

    ct = CONTENT_T
    tbl_rows = [
        ["Feature", "U-HAP", "OPA"],
        ["Policy language",       "Custom DSL (RBAC/ABAC/ACL unified)", "Rego (general-purpose)"],
        ["Evaluation model",      "Compiled indices + O(1) lookup",      "Interpreter / Rego evaluation"],
        ["Multi-model support",   "Native (unified DAG)",                "Via Rego rules (manual)"],
        ["Conflict resolution",   "Deterministic deny-override",         "Policy-author responsibility"],
        ["Update latency n=2000", "223 ms",                              "611 ms (2.73× slower)"],
        ["Post-parse n=2000",     "31 ms",                               "611 ms (19.5× slower)"],
        ["Memory (N=1000)",       "≤ 2.7 MiB",                      "Not measured"],
    ]
    add_table(sl, LMARGIN, ct, USABLE_W,
              [Inches(2.0), Inches(3.7), Inches(3.74)],
              tbl_rows, font_pt=8)


def build_slide_20(prs):
    """Backup: DSL Policy Format."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "DSL Policy Format")

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left: RBAC DSL example
    rbac_code = (
        "namespace: production\n"
        "resource: pods\n"
        "action: get\n"
        "model: rbac\n"
        "roles:\n"
        "  - developer\n"
        "  - senior_developer\n"
        "hierarchy:\n"
        "  senior_developer: [developer]"
    )
    # Gray background code box
    add_rect(sl, lx, ct, lw, Inches(0.26), fill_color=NAVY)
    add_textbox(sl, lx + Inches(0.08), ct + Pt(2), lw - Inches(0.16), Inches(0.22),
                "DSL Example — RBAC Policy",
                font_pt=9, bold=True, color=WHITE)
    code_h = Inches(1.5)
    add_rect(sl, lx, ct + Inches(0.26), lw, code_h, fill_color=GRAY, line_color=NAVY, line_pt=0.5)
    add_textbox(sl, lx + Inches(0.1), ct + Inches(0.3), lw - Inches(0.2), code_h - Inches(0.1),
                rbac_code, font_pt=8, color=NAVY_D, font_name="Courier New")

    # Right: ABAC DSL example
    abac_code = (
        "namespace: production\n"
        "resource: pods\n"
        "action: get\n"
        "model: abac\n"
        "condition:\n"
        "  AND:\n"
        "    - location: on-premise\n"
        "    - time.hour: [9, 18]"
    )
    add_rect(sl, rx, ct, rw, Inches(0.26), fill_color=NAVY)
    add_textbox(sl, rx + Inches(0.08), ct + Pt(2), rw - Inches(0.16), Inches(0.22),
                "DSL Example — ABAC Policy",
                font_pt=9, bold=True, color=WHITE)
    add_rect(sl, rx, ct + Inches(0.26), rw, code_h, fill_color=GRAY, line_color=NAVY, line_pt=0.5)
    add_textbox(sl, rx + Inches(0.1), ct + Inches(0.3), rw - Inches(0.2), code_h - Inches(0.1),
                abac_code, font_pt=8, color=NAVY_D, font_name="Courier New")

    ban_t = ct + Inches(0.26) + code_h + Inches(0.1)
    add_highlight_banner(sl, LMARGIN, ban_t, USABLE_W,
                         "The DSL is compiled once at policy-change time. No DSL parsing at request time.")


def build_slide_21(prs):
    """Backup: Implementation Details."""
    layout = prs.slide_layouts[6]
    sl = prs.slides.add_slide(layout)
    add_backup_header(sl, "Implementation Details")

    lx = LMARGIN
    lw = Inches(4.5)
    rx = Inches(5.0)
    rw = Inches(4.72)
    ct = CONTENT_T

    # Left column
    callout_box(sl, lx, ct, lw, Inches(1.2),
                "Implementation Stack",
                [
                    "Language: Python 3.11",
                    "Webhook: Flask + Gunicorn (HTTP server)",
                    "Hash consing: Python dict keyed by structural hash",
                    "Bit-vectors: Python int (arbitrary precision)",
                    "Cache: Python dict (in-process, invalidated on reload)",
                ],
                body_font_pt=8)

    callout_box(sl, lx, ct + Inches(1.27), lw, Inches(1.1),
                "Limitations",
                [
                    "Python/Gunicorn adds ~0.5–1 ms HTTP overhead per request",
                    "No cross-namespace policy composition",
                    "No dynamic reload (restart required)",
                    "No JWT validation (authentication assumed pre-handled)",
                ],
                body_font_pt=8)

    # Right column
    callout_box(sl, rx, ct, rw, Inches(1.1),
                "Test Coverage",
                [
                    "S1–S7: 7 correctness scenarios (all pass)",
                    "Hash consing: P1–P4 example = 8 DAG nodes (verified)",
                    "3 experiments: N=10–2000, k=5–320",
                    "100/100 equivalence checks vs. OPA (Exp3)",
                ],
                body_font_pt=8)

    callout_box(sl, rx, ct + Inches(1.17), rw, Inches(1.1),
                "Deployment",
                [
                    "Kubernetes ValidatingWebhookConfiguration",
                    "HTTPS endpoint: /authorize",
                    "Health check: /healthz",
                    "Container: standard Python image",
                ],
                body_font_pt=8)


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    prs = Presentation()
    prs.slide_width  = W
    prs.slide_height = H

    builders = [
        build_slide_01,           # 1  Title
        build_slide_background,   # 2  Background
        build_slide_related_work, # 3  Related Work
        build_slide_02,           # 4  Motivation
        build_slide_03,           # 5  Solution
        build_slide_04,           # 6  Architecture
        build_slide_05,           # 7  Hash Consing
        build_slide_06,           # 8  Pruning
        build_slide_07,           # 9  Evaluation Setup
        build_slide_08,           # 10 Exp1
        build_slide_09,           # 11 Exp2
        build_slide_10,           # 12 Exp3
        build_slide_11,           # 13 Conclusion
        build_slide_references,   # 14 References
        build_slide_12,           # 15 Thank You
        build_slide_13,           # 16 Backup: Runtime eval order
        build_slide_14,           # 17 Backup: S1–S7
        build_slide_15,           # 18 Backup: Hash consing example
        build_slide_16,           # 19 Backup: RBAC bit-vector
        build_slide_17,           # 20 Backup: Memory footprint
        build_slide_18,           # 21 Backup: Cache impact
        build_slide_19,           # 22 Backup: OPA comparison
        build_slide_20,           # 23 Backup: DSL format
        build_slide_21,           # 24 Backup: Implementation details
    ]

    for i, fn in enumerate(builders, start=1):
        print(f"  Building slide {i:02d}: {fn.__name__} ...", end=" ", flush=True)
        fn(prs)
        print("OK")

    prs.save(str(OUT))
    size_kb = OUT.stat().st_size // 1024
    print(f"\nSaved: {OUT}")
    print(f"Slides: {len(prs.slides)}")
    print(f"File size: {size_kb} KiB")

    if WARNINGS:
        print(f"\nWarnings ({len(WARNINGS)}):")
        for w in WARNINGS:
            print(f"  ! {w}")
    else:
        print("\nNo warnings.")


if __name__ == "__main__":
    main()
