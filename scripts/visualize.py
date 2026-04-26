#!/usr/bin/env python3
"""
visualize.py — U-HAP categorical column-layout renderer.

Generates clean PNG diagrams with left-to-right layout:
  Subject/Section | Attr/Role circles | Gate expr (ABAC) | Resource

Outputs:
  output/graphs/prod-pods.png
  output/graphs/dev-pods.png
  output/graphs/prod-secrets.png
  output/graphs/hash-consing-prod-pods.png
  output/graphs/example_overview.png
  output/graphs/example_ecommerce.png
  output/graphs/example_healthcare.png

Usage:
    python scripts/visualize.py
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))


def _chk(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


if not _chk("matplotlib"):
    print("ERROR: pip install matplotlib")
    sys.exit(1)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Circle
import matplotlib.patches as mpatches

from dsl.loader import load_file
from graph.builder import build_graph
from graph.models import PolicyGraph
from engine.gate_nodes import AtomicCheck, GateNode, ThresholdGate

# ═══════════════════════════════════════════════════════════════════
# COLOR PALETTE  (matching mermaid diagram)
# ═══════════════════════════════════════════════════════════════════
ATTR_COLORS = ["#7CDB6A", "#F69C54", "#8BA3FF", "#FFD93D", "#C9B1FF", "#80DEEA"]
C_ROLE      = "#18C1D6"   # RBAC / HIER roles  (cyan)
C_ACL       = "#DDA8F4"   # ACL subjects        (purple)
C_DENY_SUB  = "#FF6B6B"   # DENY subjects       (red)

SEC_BG = {
    "ABAC": "#F1F8E9", "RBAC": "#E3F2FD",
    "HIER": "#F3E5F5", "ACL":  "#FFFDE7", "DENY": "#FFEBEE",
}
SEC_BORDER = {
    "ABAC": "#66BB6A", "RBAC": "#42A5F5",
    "HIER": "#AB47BC", "ACL":  "#FFA726", "DENY": "#EF5350",
}
SEC_LC = {
    "ABAC": "#2E7D32", "RBAC": "#1565C0",
    "HIER": "#6A1B9A", "ACL":  "#E65100", "DENY": "#B71C1C",
}

# ═══════════════════════════════════════════════════════════════════
# LAYOUT CONSTANTS  (data-coordinate units; aspect="equal" ensures
#                    1 data-unit x == 1 data-unit y → true circles)
# ═══════════════════════════════════════════════════════════════════
TOTAL_W  = 14.5   # canvas width
X_SEC    = 0.55   # section label x
X_CIRC0  = 3.0    # first attribute/role circle center
CIR_STEP = 1.0    # gap between side-by-side circles
CIR_R    = 0.40   # circle radius
X_GATE   = 7.6    # gate-box center x
GATE_W   = 2.7    # gate-box width
GATE_H   = 0.70   # gate-box height
X_RES    = 12.4   # resource-box center x
RES_W    = 1.9    # resource-box width
RES_H    = 1.0    # resource-box height
ROW_H    = 1.45   # vertical space per row
SEC_H    = 0.75   # extra height for section header
SCALE    = 0.80   # inches per data unit
FIG_DPI  = 150


# ═══════════════════════════════════════════════════════════════════
# DRAWING PRIMITIVES
# ═══════════════════════════════════════════════════════════════════

def rrect(ax, cx, cy, w, h, fc, ec, lw=1.5, z=2, alpha=1.0):
    p = FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h,
        boxstyle="round,pad=0.07",
        facecolor=fc, edgecolor=ec, linewidth=lw, zorder=z, alpha=alpha,
    )
    ax.add_patch(p)


def circ(ax, cx, cy, fc, ec="black", lw=1.5, z=3):
    ax.add_patch(Circle((cx, cy), CIR_R, facecolor=fc, edgecolor=ec,
                        linewidth=lw, zorder=z))


def txt(ax, x, y, t, size=8, color="black",
        ha="center", va="center", bold=False, z=5):
    kw = {"ha": ha, "va": va, "fontsize": size, "color": color,
          "zorder": z, "clip_on": False}
    if bold:
        kw["fontweight"] = "bold"
    ax.text(x, y, t, **kw)


def _ann(ax, x1, y1, x2, y2, color, lw, ls, rad, z=4):
    ax.annotate(
        "", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle="->", color=color, lw=lw,
            linestyle=ls,
            connectionstyle=f"arc3,rad={rad}",
        ),
        zorder=z, annotation_clip=False,
    )


def arrow(ax, x1, y1, x2, y2, color="black", dashed=False,
          lw=1.5, rad=0.0):
    ls = (0, (4, 3)) if dashed else "-"
    _ann(ax, x1, y1, x2, y2, color, lw, ls, rad)


def arrow_lbl(ax, x1, y1, x2, y2, label, allow=None,
              color="black", dashed=False, lw=1.5, rad=0.0):
    arrow(ax, x1, y1, x2, y2, color=color, dashed=dashed, lw=lw, rad=rad)
    mx = (x1 + x2) / 2
    my = (y1 + y2) / 2 + 0.22
    sfx = " [ALLOW]" if allow is True else (" [DENY]" if allow is False else "")
    txt(ax, mx, my, label + sfx, size=6.5, color=color)


# ═══════════════════════════════════════════════════════════════════
# GATE EXPRESSION HELPERS
# ═══════════════════════════════════════════════════════════════════

def collect_attrs(node):
    seen, result = set(), []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, AtomicCheck):
            if n.attribute not in seen:
                seen.add(n.attribute)
                result.append(n.attribute)
        elif hasattr(n, "children"):
            stack.extend(n.children)
    return result


def gate_expr(node, depth=0):
    if isinstance(node, AtomicCheck):
        v = node.value
        if isinstance(v, str):
            v = f"'{v}'"
        return f"{node.attribute}{node.operator}{v}"
    elif isinstance(node, GateNode):
        op = "\u2227" if node.operator.upper() == "AND" else "\u2228"
        parts = [gate_expr(c, depth + 1) for c in node.children]
        s = f" {op} ".join(parts)
        return f"({s})" if depth > 0 else s
    elif isinstance(node, ThresholdGate):
        parts = [gate_expr(c, depth + 1) for c in node.children]
        return f"\u2265{node.k}({', '.join(parts)})"
    return "?"


def _abbrev(s, n=34):
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def _circ_lbl(s, n=9):
    return s if len(s) <= n else s[: n - 1] + "\u2026"


# ═══════════════════════════════════════════════════════════════════
# HIERARCHY CHAIN EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def hier_chains(hier_edges):
    all_children = set()
    for ch in hier_edges.values():
        all_children.update(ch)
    roots = [p for p in hier_edges if p not in all_children]
    chains = []
    for root in roots:
        chain = [root]
        cur = root
        while cur in hier_edges and hier_edges[cur]:
            cur = hier_edges[cur][0]
            chain.append(cur)
            if len(chain) > 10:
                break
        chains.append(chain)
    return chains


# ═══════════════════════════════════════════════════════════════════
# POLICYGRAPH → SECTIONS LIST
# ═══════════════════════════════════════════════════════════════════

def pg_to_sections(pg: PolicyGraph):
    """Convert a PolicyGraph to a list of section dicts for rendering."""
    attr_color_map, cidx = {}, [0]

    def gc(attr):
        if attr not in attr_color_map:
            attr_color_map[attr] = ATTR_COLORS[cidx[0] % len(ATTR_COLORS)]
            cidx[0] += 1
        return attr_color_map[attr]

    sections = []

    # ── ABAC ──
    rows = []
    for action, ges in sorted(pg.gate_edges.items()):
        for ge in ges:
            attrs = collect_attrs(ge.gate_root)
            rows.append({
                "circles": [(_circ_lbl(a), gc(a)) for a in attrs],
                "gate":    _abbrev(gate_expr(ge.gate_root)),
                "action":  action,
                "allow":   True,
                "chain":   None,
            })
    if rows:
        sections.append({"type": "ABAC", "rows": rows})

    # ── RBAC ──
    rows = []
    for (role, action) in sorted(pg.perm_edges.keys()):
        rows.append({
            "circles": [(_circ_lbl(role), C_ROLE)],
            "gate":    None,
            "action":  action,
            "allow":   True,
            "chain":   None,
        })
    if rows:
        sections.append({"type": "RBAC", "rows": rows})

    # ── HIER ──
    rows = []
    for chain in hier_chains(pg.hier_edges):
        leaf = chain[-1]
        acts = sorted({a for (r, a) in pg.perm_edges if r == leaf})
        rows.append({
            "circles": [],
            "gate":    None,
            "action":  ",".join(acts) if acts else "inherits",
            "allow":   True,
            "chain":   chain,
        })
    if rows:
        sections.append({"type": "HIER", "rows": rows})

    # ── ACL ──
    acl_by = {}
    for (subj, action) in pg.acl_edges:
        acl_by.setdefault(subj, []).append(action)
    rows = []
    for subj, acts in sorted(acl_by.items()):
        rows.append({
            "circles": [(_circ_lbl(subj), C_ACL)],
            "gate":    None,
            "action":  ",".join(sorted(acts)),
            "allow":   True,
            "chain":   None,
        })
    if rows:
        sections.append({"type": "ACL", "rows": rows})

    # ── DENY ──
    deny_by = {}
    for (subj, action) in pg.deny_edges:
        deny_by.setdefault(subj, []).append(action)
    rows = []
    for subj, acts in sorted(deny_by.items()):
        rows.append({
            "circles": [(_circ_lbl(subj), C_DENY_SUB)],
            "gate":    None,
            "action":  ",".join(sorted(acts)),
            "allow":   False,
            "chain":   None,
        })
    if rows:
        sections.append({"type": "DENY", "rows": rows})

    return sections


# ═══════════════════════════════════════════════════════════════════
# ROW DRAWING HELPERS
# ═══════════════════════════════════════════════════════════════════

def _draw_row(ax, row_y, row, res_y, stype):
    circles = row["circles"]
    gate    = row.get("gate")
    action  = row.get("action", "")
    allow   = row.get("allow", True)

    n  = len(circles)
    x0 = X_CIRC0 - (n - 1) * CIR_STEP / 2

    # Draw attribute/role circles
    for i, (label, color) in enumerate(circles):
        cx = x0 + i * CIR_STEP
        circ(ax, cx, row_y, color, z=4)
        txt(ax, cx, row_y, label, size=6.5, bold=True, z=5)

    edge_c  = SEC_BORDER.get(stype, "black")
    deny_c  = "#C0392B"
    final_c = deny_c if not allow else edge_c
    last_cx = (x0 + (n - 1) * CIR_STEP) if n > 0 else X_CIRC0

    if gate:
        # Circles → gate box
        arrow(ax, last_cx + CIR_R, row_y,
              X_GATE - GATE_W / 2 - 0.05, row_y,
              color="#999999", lw=1.2)
        # Gate box (red border for deny, black otherwise)
        gate_ec = deny_c if not allow else "black"
        rrect(ax, X_GATE, row_y, GATE_W, GATE_H, "white", gate_ec, lw=1.5, z=3)
        txt(ax, X_GATE, row_y, gate, size=6.0, z=5)
        # Gate → resource
        arrow_lbl(ax, X_GATE + GATE_W / 2 + 0.05, row_y,
                  X_RES - RES_W / 2 - 0.08, res_y,
                  action, allow=allow, color=final_c, rad=-0.08)
    elif not allow:
        # DENY: circle → deny terminal box → resource (with ❌)
        dt_x = X_GATE
        arrow(ax, last_cx + CIR_R, row_y,
              dt_x - GATE_W / 2 - 0.05, row_y,
              color=deny_c, lw=1.3)
        rrect(ax, dt_x, row_y, GATE_W, GATE_H, "white", deny_c, lw=2.0, z=3)
        txt(ax, dt_x, row_y + 0.14, "Deny terminal (d)", size=6.0, z=5)
        txt(ax, dt_x, row_y - 0.18, "Unconditional", size=5.5, color="#666", z=5)
        arrow_lbl(ax, dt_x + GATE_W / 2 + 0.05, row_y,
                  X_RES - RES_W / 2 - 0.08, res_y,
                  action, allow=False, color=deny_c, rad=-0.08)
    else:
        # RBAC / ACL: circle → resource directly
        arrow_lbl(ax, last_cx + CIR_R, row_y,
                  X_RES - RES_W / 2 - 0.08, res_y,
                  action, allow=True, color=edge_c, rad=0.0)


def _draw_hier_row(ax, row_y, row, res_y):
    chain  = row["chain"]
    action = row.get("action", "inherits")
    n      = len(chain)

    # Spread chain from X_CIRC0 to X_GATE+0.8
    x_end = X_GATE + 0.9
    positions = (
        [X_CIRC0]
        if n == 1
        else [X_CIRC0 + i * (x_end - X_CIRC0) / (n - 1) for i in range(n)]
    )

    for i, (role, x) in enumerate(zip(chain, positions)):
        circ(ax, x, row_y, C_ROLE, ec=SEC_BORDER["HIER"], z=4)
        txt(ax, x, row_y, _circ_lbl(role), size=6.0, bold=True, z=5)
        if i < n - 1:
            nx_x = positions[i + 1]
            arrow(ax, x + CIR_R, row_y, nx_x - CIR_R, row_y,
                  color=SEC_BORDER["HIER"], lw=1.3)
            txt(ax, (x + nx_x) / 2, row_y + 0.30,
                "E_hier", size=5.5, color="#999999")

    last_x = positions[-1] + CIR_R if positions else X_CIRC0
    arrow_lbl(ax, last_x, row_y,
              X_RES - RES_W / 2 - 0.08, res_y,
              action, allow=True, color=SEC_BORDER["HIER"], rad=-0.06)


# ═══════════════════════════════════════════════════════════════════
# MAIN RENDER FUNCTION
# ═══════════════════════════════════════════════════════════════════

def render_diagram(title, resource_name, sections, output_path):
    """Render a categorical column-layout diagram to a PNG file."""
    if not sections:
        print(f"  (skipped — no sections for {output_path})")
        return

    total_rows = sum(len(s["rows"]) for s in sections)
    total_H    = total_rows * ROW_H + len(sections) * SEC_H + 1.6

    # Equal-aspect figure so matplotlib Circle patches render as circles
    fig_w = SCALE * TOTAL_W
    fig_h = SCALE * total_H
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=FIG_DPI)
    ax.set_xlim(0, TOTAL_W)
    ax.set_ylim(0, total_H)
    ax.set_aspect("equal", adjustable="box")
    ax.axis("off")
    fig.suptitle(title, fontsize=11, fontweight="bold", y=0.995)

    # ── Resource box (right, vertically centred) ──
    res_y = total_H / 2
    rrect(ax, X_RES, res_y, RES_W, RES_H * 1.3, "white", "black", lw=2.5, z=2)
    txt(ax, X_RES, res_y + 0.22, resource_name, size=9, bold=True)
    txt(ax, X_RES, res_y - 0.22, "(Resource)", size=6.5, color="#555555")

    # ── Sections (top → bottom) ──
    band_right = X_RES - RES_W / 2 - 0.5   # bands don't overlap resource
    y_cur = total_H - 0.95

    for sec in sections:
        stype = sec["type"]
        rows  = sec["rows"]
        n     = len(rows)
        sec_h = n * ROW_H + SEC_H

        # Section background band
        bx = (band_right) / 2 + 0.1
        rrect(ax, bx, y_cur - sec_h / 2 + 0.08,
              band_right - 0.2, sec_h - 0.16,
              SEC_BG[stype], SEC_BORDER[stype], lw=1.0, z=1, alpha=0.55)

        # Section label (left side, vertically centred in header strip)
        txt(ax, X_SEC, y_cur - SEC_H / 2, stype,
            size=9, bold=True, color=SEC_LC[stype], ha="left")

        y_cur -= SEC_H

        for row in rows:
            row_y = y_cur - ROW_H / 2
            if row.get("chain"):
                _draw_hier_row(ax, row_y, row, res_y)
            else:
                _draw_row(ax, row_y, row, res_y, stype)
            y_cur -= ROW_H

    # ── Legend ──
    leg = [
        mpatches.Patch(facecolor=ATTR_COLORS[0], edgecolor="#333",
                       label="ABAC attribute"),
        mpatches.Patch(facecolor=C_ROLE, edgecolor="#333",
                       label="RBAC / HIER role"),
        mpatches.Patch(facecolor=C_ACL, edgecolor="#333",
                       label="ACL subject"),
        mpatches.Patch(facecolor=C_DENY_SUB, edgecolor="#333",
                       label="DENY subject"),
        mpatches.Patch(facecolor="white", edgecolor="black",
                       label="Gate / Resource node"),
    ]
    ax.legend(handles=leg, loc="lower right", fontsize=6.5,
              framealpha=0.92, ncol=2, bbox_to_anchor=(1.0, 0.0))

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    plt.savefig(output_path, dpi=FIG_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {output_path}")


# ═══════════════════════════════════════════════════════════════════
# CONCEPTUAL / EXAMPLE DIAGRAMS  (hardcoded — no YAML needed)
# ═══════════════════════════════════════════════════════════════════

def render_conceptual_overview(output_path):
    """Mermaid-style combined diagram showing all 5 U-HAP policy models."""
    sections = [
        {
            "type": "ABAC",
            "rows": [
                {
                    "circles": [("net", "#7CDB6A"), ("time", "#F69C54")],
                    "gate":    "net='on-prem' \u2227 time='biz-hrs'",
                    "action":  "get",
                    "allow":   True,
                    "chain":   None,
                },
                {
                    "circles": [("dept", "#8BA3FF"), ("clr", "#FFD93D")],
                    "gate":    "dept='eng' \u2227 clr='top-sec'",
                    "action":  "delete",
                    "allow":   True,
                    "chain":   None,
                },
            ],
        },
        {
            "type": "RBAC",
            "rows": [
                {"circles": [("\u03c11", C_ROLE)], "gate": None,
                 "action": "a4", "allow": True, "chain": None},
            ],
        },
        {
            "type": "HIER",
            "rows": [
                {"circles": [], "gate": None,
                 "action": "a5 (inherited)", "allow": True,
                 "chain": ["\u03c12", "\u03c13", "\u03c14"]},
            ],
        },
        {
            "type": "ACL",
            "rows": [
                {"circles": [("user", C_ACL)], "gate": None,
                 "action": "a6", "allow": True, "chain": None},
            ],
        },
        {
            "type": "DENY",
            "rows": [
                {"circles": [("*(all)", C_DENY_SUB)], "gate": None,
                 "action": "a7", "allow": False, "chain": None},
            ],
        },
    ]
    render_diagram(
        "U-HAP: Conceptual Overview — All 5 Policy Models on Resource A",
        "Resource A",
        sections,
        output_path,
    )


def render_example_ecommerce(output_path):
    """E-commerce orders policy example."""
    sections = [
        {
            "type": "ABAC",
            "rows": [
                {
                    "circles": [("country", "#7CDB6A"), ("tier", "#F69C54")],
                    "gate":    "country='US' \u2227 tier='premium'",
                    "action":  "view-orders",
                    "allow":   True,
                    "chain":   None,
                },
                {
                    "circles": [("tier", "#F69C54"), ("verified", "#8BA3FF")],
                    "gate":    "tier='premium' \u2227 verified='true'",
                    "action":  "bulk-export",
                    "allow":   True,
                    "chain":   None,
                },
            ],
        },
        {
            "type": "RBAC",
            "rows": [
                {"circles": [("seller", C_ROLE)], "gate": None,
                 "action": "create", "allow": True, "chain": None},
                {"circles": [("buyer", C_ROLE)],  "gate": None,
                 "action": "read",   "allow": True, "chain": None},
            ],
        },
        {
            "type": "HIER",
            "rows": [
                {"circles": [], "gate": None,
                 "action": "manage (inherited)", "allow": True,
                 "chain": ["admin", "manager", "staff"]},
            ],
        },
        {
            "type": "ACL",
            "rows": [
                {"circles": [("pay-svc", C_ACL)], "gate": None,
                 "action": "process-pmt", "allow": True, "chain": None},
                {"circles": [("audit-bot", C_ACL)], "gate": None,
                 "action": "read", "allow": True, "chain": None},
            ],
        },
        {
            "type": "DENY",
            "rows": [
                {"circles": [("*(all)", C_DENY_SUB)], "gate": None,
                 "action": "export-raw", "allow": False, "chain": None},
                {"circles": [("extern-api", C_DENY_SUB)], "gate": None,
                 "action": "delete", "allow": False, "chain": None},
            ],
        },
    ]
    render_diagram(
        "U-HAP Example: E-Commerce Orders Policy",
        "Orders",
        sections,
        output_path,
    )


def render_example_healthcare(output_path):
    """Healthcare patient-records policy example."""
    sections = [
        {
            "type": "ABAC",
            "rows": [
                {
                    "circles": [("dept", "#7CDB6A"), ("role_attr", "#F69C54")],
                    "gate":    "dept='cardiology' \u2227 role='doctor'",
                    "action":  "read",
                    "allow":   True,
                    "chain":   None,
                },
                {
                    "circles": [("dept", "#7CDB6A"), ("shift", "#8BA3FF")],
                    "gate":    "dept='cardiology' \u2227 shift='active'",
                    "action":  "update",
                    "allow":   True,
                    "chain":   None,
                },
                {
                    "circles": [("cleared", "#FFD93D"), ("dept", "#7CDB6A")],
                    "gate":    "cleared='true' \u2227 dept='cardiology'",
                    "action":  "prescribe",
                    "allow":   True,
                    "chain":   None,
                },
            ],
        },
        {
            "type": "RBAC",
            "rows": [
                {"circles": [("nurse", C_ROLE)], "gate": None,
                 "action": "read", "allow": True, "chain": None},
                {"circles": [("pharmacist", C_ROLE)], "gate": None,
                 "action": "read,dispense", "allow": True, "chain": None},
            ],
        },
        {
            "type": "HIER",
            "rows": [
                {"circles": [], "gate": None,
                 "action": "read,update,delete (inherited)", "allow": True,
                 "chain": ["chief-dr", "attending", "resident"]},
            ],
        },
        {
            "type": "ACL",
            "rows": [
                {"circles": [("pt-portal", C_ACL)], "gate": None,
                 "action": "read-own", "allow": True, "chain": None},
                {"circles": [("audit-bot", C_ACL)], "gate": None,
                 "action": "read", "allow": True, "chain": None},
            ],
        },
        {
            "type": "DENY",
            "rows": [
                {"circles": [("*(all)", C_DENY_SUB)], "gate": None,
                 "action": "bulk-delete", "allow": False, "chain": None},
                {"circles": [("ext-api", C_DENY_SUB)], "gate": None,
                 "action": "export", "allow": False, "chain": None},
            ],
        },
    ]
    render_diagram(
        "U-HAP Example: Healthcare Patient Records Policy",
        "patient-records",
        sections,
        output_path,
    )


def render_example_k8s_rbac(output_path):
    """Kubernetes-style multi-role RBAC + HIER + DENY example."""
    sections = [
        {
            "type": "ABAC",
            "rows": [
                {
                    "circles": [("ns", "#7CDB6A"), ("env", "#F69C54")],
                    "gate":    "ns='prod' \u2227 env='production'",
                    "action":  "exec",
                    "allow":   True,
                    "chain":   None,
                },
            ],
        },
        {
            "type": "RBAC",
            "rows": [
                {"circles": [("viewer", C_ROLE)],    "gate": None,
                 "action": "get,list", "allow": True, "chain": None},
                {"circles": [("developer", C_ROLE)], "gate": None,
                 "action": "get,list,create", "allow": True, "chain": None},
                {"circles": [("sre", C_ROLE)],       "gate": None,
                 "action": "get,list,delete", "allow": True, "chain": None},
            ],
        },
        {
            "type": "HIER",
            "rows": [
                {"circles": [], "gate": None,
                 "action": "get,list,create,update,delete (inherited)",
                 "allow": True,
                 "chain": ["cluster-admin", "namespace-admin", "sre", "developer"]},
            ],
        },
        {
            "type": "ACL",
            "rows": [
                {"circles": [("cicd-bot", C_ACL)], "gate": None,
                 "action": "create,update", "allow": True, "chain": None},
                {"circles": [("monitor", C_ACL)], "gate": None,
                 "action": "get,list", "allow": True, "chain": None},
            ],
        },
        {
            "type": "DENY",
            "rows": [
                {"circles": [("*(all)", C_DENY_SUB)], "gate": None,
                 "action": "deletecollection", "allow": False, "chain": None},
                {"circles": [("intern", C_DENY_SUB)], "gate": None,
                 "action": "delete", "allow": False, "chain": None},
            ],
        },
    ]
    render_diagram(
        "U-HAP Example: Kubernetes Pod Policy (Multi-Role)",
        "pods",
        sections,
        output_path,
    )


# ═══════════════════════════════════════════════════════════════════
# HASH CONSING DAG RENDERER
# ═══════════════════════════════════════════════════════════════════

def render_hc_dag(hc_registry, title, output_path):
    """Render hash consing shared ABAC DAG using networkx."""
    if not _chk("networkx"):
        print("WARNING: pip install networkx  (needed for hash-consing DAG)")
        return

    import networkx as nx

    G      = nx.DiGraph()
    labels = {}
    colors = {}

    def nid(node):
        return str(node.canonical_key())

    for _key, node in hc_registry._memo.items():
        i = nid(node)
        G.add_node(i)
        if isinstance(node, AtomicCheck):
            v = f"'{node.value}'" if isinstance(node.value, str) else node.value
            labels[i] = f"{node.attribute}{node.operator}{v}"
            colors[i] = "#FFF9C4"   # pale yellow
        elif isinstance(node, GateNode):
            labels[i] = node.operator
            colors[i] = "#BBDEFB"   # pale blue
        elif isinstance(node, ThresholdGate):
            labels[i] = f"\u2265{node.k}"
            colors[i] = "#BBDEFB"

    for _key, node in hc_registry._memo.items():
        if hasattr(node, "children"):
            pid = nid(node)
            for child in node.children:
                cid = nid(child)
                if cid in G:
                    G.add_edge(pid, cid)

    if not G.nodes:
        print("  (skipped — empty hash-consing registry)")
        return

    # Layout preference: graphviz dot → spring fallback
    pos = None
    if _chk("pygraphviz"):
        try:
            pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
        except Exception:
            pass
    if pos is None and _chk("pydot"):
        try:
            pos = nx.nx_pydot.graphviz_layout(G, prog="dot")
        except Exception:
            pass
    if pos is None:
        pos = nx.spring_layout(G, seed=42, k=2.5)

    n      = len(G.nodes)
    fig_w  = max(9, n * 1.6)
    fig_h  = max(6, n * 1.0)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=FIG_DPI)
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.axis("off")

    node_c = [colors.get(nd, "#EEEEEE") for nd in G.nodes()]
    nx.draw_networkx_nodes(G, pos, node_color=node_c, node_size=2400,
                           edgecolors="#444444", linewidths=1.8, ax=ax)
    nx.draw_networkx_labels(
        G, pos,
        labels={nd: labels.get(nd, nd) for nd in G.nodes()},
        font_size=7, ax=ax,
    )
    if G.edges():
        nx.draw_networkx_edges(
            G, pos,
            edge_color="#42A5F5",
            style="solid",
            arrows=True,
            arrowsize=20,
            connectionstyle="arc3,rad=0.05",
            ax=ax,
        )

    n_atom = sum(1 for nd in G.nodes() if colors.get(nd) == "#FFF9C4")
    n_gate = sum(1 for nd in G.nodes() if colors.get(nd) == "#BBDEFB")
    ax.text(
        0.5, -0.03,
        f"{len(G.nodes)} total nodes  ({n_atom} atomic, {n_gate} gate)"
        f"  \u2014  shared via hash consing",
        transform=ax.transAxes,
        ha="center", fontsize=8, style="italic", color="#555555",
    )

    leg = [
        mpatches.Patch(facecolor="#FFF9C4", edgecolor="#444", label="Atomic check"),
        mpatches.Patch(facecolor="#BBDEFB", edgecolor="#444", label="AND / OR gate"),
    ]
    ax.legend(handles=leg, loc="lower left", fontsize=7.5, framealpha=0.9)

    plt.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    plt.savefig(output_path, dpi=FIG_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {output_path}")


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    policies_dir = os.path.join(PROJECT_ROOT, "deploy", "sample-policies")
    output_dir   = os.path.join(PROJECT_ROOT, "output", "graphs")
    os.makedirs(output_dir, exist_ok=True)

    # ── Actual policy graphs ──
    policy_files = [
        ("prod-pods.yaml",    "prod", "pods",    "prod-pods"),
        ("dev-pods.yaml",     "dev",  "pods",    "dev-pods"),
        ("prod-secrets.yaml", "prod", "secrets", "prod-secrets"),
    ]

    for yaml_name, ns, res, stem in policy_files:
        yaml_path = os.path.join(policies_dir, yaml_name)
        if not os.path.isfile(yaml_path):
            print(f"WARNING: {yaml_path} not found")
            continue

        records = load_file(yaml_path)
        if not records:
            print(f"WARNING: no records in {yaml_name}")
            continue

        pg       = build_graph(records, namespace=ns, resource=res)
        sections = pg_to_sections(pg)
        title    = f"U-HAP Policy Graph  G_({{{ns},{res}}})"
        render_diagram(title, f"{ns}/{res}", sections,
                       os.path.join(output_dir, f"{stem}.png"))

        # Hash consing DAG for prod-pods
        if stem == "prod-pods":
            hc = getattr(pg, "_hc_registry", None)
            if hc is not None and hc.node_count > 0:
                render_hc_dag(
                    hc,
                    "Hash Consing Shared ABAC DAG \u2014 prod/pods",
                    os.path.join(output_dir, "hash-consing-prod-pods.png"),
                )
            else:
                print("WARNING: no ABAC hash consing registry for prod-pods")

    # ── Conceptual / example diagrams ──
    render_conceptual_overview(
        os.path.join(output_dir, "example_overview.png"))
    render_example_ecommerce(
        os.path.join(output_dir, "example_ecommerce.png"))
    render_example_healthcare(
        os.path.join(output_dir, "example_healthcare.png"))
    render_example_k8s_rbac(
        os.path.join(output_dir, "example_k8s_rbac.png"))


if __name__ == "__main__":
    main()
