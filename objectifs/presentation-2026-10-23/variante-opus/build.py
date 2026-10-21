"""Variante Opus — 2026-10-23 progress deck, rebuilt on an explicit grid.

Same content and same visual family as ../build.py (SMart ILIA / UMONS
template), but every slide is composed on one 12-column grid with a fixed
vertical structure: top bar / title zone / body zone / caption zone / footer.

Run:  python3 build.py
"""

import functools
import io
import json
import os
import pathlib
import subprocess
import tempfile
import csv

from PIL import ImageFont

CM = 72 / 2.54  # points per centimetre
_ARIAL = "/System/Library/Fonts/Supplemental/Arial.ttf"
_ARIAL_BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"


@functools.lru_cache(maxsize=None)
def _font(size, bold):
    return ImageFont.truetype(_ARIAL_BOLD if bold else _ARIAL, int(size * 10))


def _wrap(text, limit_pt, size, bold):
    """Greedy word wrap; returns the list of lines at that point size."""
    font = _font(size, bold)
    lines = []
    for para in text.split("\n"):
        if not para:
            lines.append("")
            continue
        line = ""
        for word in para.split(" "):
            trial = f"{line} {word}" if line else word
            if font.getlength(trial) / 10 <= limit_pt or not line:
                line = trial
            else:
                lines.append(line)
                line = word
        lines.append(line)
    return lines


def fit_size(text, w_cm, h_cm, size, bold=False, pad_cm=0.12):
    """Largest point size, at most `size`, at which `text` fits the box.

    officecli emits normAutofit but the HTML renderer ignores the stored
    fontScale and `autoFit="shrink"` does nothing, so the size has to be right
    in the document itself. The headless renderer also substitutes a wider
    fallback face for Arial: both the measured width and the line height are
    inflated on purpose.
    """
    if not text:
        return size
    WIDTH_SLACK, LINE_FACTOR = 1.18, 1.55
    limit_w = (w_cm - 2 * pad_cm) * CM / WIDTH_SLACK
    limit_h = (h_cm - 0.06) * CM
    s = float(size)
    while s > 7:
        lines = _wrap(text, limit_w, s, bold)
        if all(_font(s, bold).getlength(ln) / 10 <= limit_w for ln in lines):
            if len(lines) * s * LINE_FACTOR <= limit_h:
                return s
        s -= 0.5
    return 7.0


ROOT = pathlib.Path(__file__).resolve().parent
FILE = ROOT / "slides.pptx"
LOGO = pathlib.Path(
    "/Users/tanguyvans/Documents/thèse/output/presentation/reference/logo-001.png"
)

# Palette, identical to the template.
R = "B60036"      # crimson accent
B = "1D5C96"      # blue accent
INK = "20252D"
M = "5C626C"      # muted grey
ROSE = "FCF0F4"
BLUE = "EFF6FC"
GRAY = "F6F7F9"
LINE = "D9DEE5"
GREEN = "2E7D5B"
FONT = "Arial"

SECTIONS = ["Objective", "Instrument", "Hypotheses", "Outlook"]

# ---------------------------------------------------------------- the grid
# 12 columns, 0.56 cm gutters, 2.2 cm side margins. Every slide uses the same
# horizontal stations; only the vertical partition changes.
ML, MR = 2.2, 2.2
CW = 33.866667 - ML - MR          # 29.4667 cm of content
NC, GUT = 12, 0.56
COLW = (CW - (NC - 1) * GUT) / NC  # 1.9422 cm
PITCH = COLW + GUT


def cx(i):
    """Left edge of column i (0-based)."""
    return ML + i * PITCH


def cw(n):
    """Width of an n-column span."""
    return n * COLW + (n - 1) * GUT


RIGHT = ML + CW                   # 31.6667

# The two horizontal stations reused by every split slide.
TEXT_X, TEXT_W = ML, cw(5)                              # 2.20 .. 14.15
DIAG_X, DIAG_W = cx(5), cw(7)                           # 14.71 .. 31.67

# The fixed vertical structure.
TITLE_Y, TITLE_H = 1.70, 1.80
RULE_Y = 3.62                     # crimson rule under the title
BODY_Y = 4.45
BODY_BOTTOM = 14.55
CAP_RULE_Y = 14.82                # hairline that opens the caption band
CAP_Y, CAP_H = 14.90, 1.55
SUB_Y, SUB_H = 16.50, 0.62
FOOT_Y = 17.90

slides = []
ops = []
s = 0
section = 0


def command(op, path=None, **kw):
    d = {"command": op}
    if path is not None:
        d["path"] = path
    d.update(kw)
    ops.append(d)


def add(typ, **props):
    command(
        "add",
        parent=f"/slide[{s}]",
        type=typ,
        props={
            k: (str(v).lower() if isinstance(v, bool) else str(v))
            for k, v in props.items()
        },
    )


def box(text, x, y, w, h, size=18, color=INK, fill="none", bold=False,
        align="left", name=None, line="none", preset="rect", margin="0cm",
        valign="middle", italic=False):
    add(
        "shape",
        name=name or f"Element-{len(ops)}",
        text=text,
        x=f"{x}cm", y=f"{y}cm", width=f"{w}cm", height=f"{h}cm",
        font=FONT,
        size=fit_size(text, w, h, size, bold) if text else size,
        color=color, fill=fill, bold=bold,
        italic=italic, align=align, valign=valign, margin=margin,
        line=line, preset=preset,
        autoFit="none",
    )


def panel(x, y, w, h, fill=GRAY, line_color=LINE, preset="roundRect"):
    box("", x, y, w, h, fill=fill, line=f"{line_color}:1pt", preset=preset)


def stem(x, y, w, h, color=R):
    """Explicit rule, used instead of connectors (which cut across boxes)."""
    box("", x, y, w, h, fill=color)


def picture(path, x, y, w, h, alt=""):
    add("picture", src=str(path), x=f"{x}cm", y=f"{y}cm",
        width=f"{w}cm", height=f"{h}cm", alt=alt)


def page(title, notes="", seconds=60, sect=None, chrome=True):
    global ops, s, section
    ops = []
    s += 1
    if sect is not None:
        section = sect
    command("add", parent="/", type="slide",
            props={"layout": "blank", "background": "FFFFFF"})
    command("get", path=f"/slide[{s}]", depth=0)

    add("notes",
        text=f"Duration: about {seconds} seconds.\n{notes}".strip(),
        lang="en-US")

    if not chrome:
        slides.append({"title": title, "ops": ops, "notes": notes,
                       "seconds": seconds})
        return

    picture(LOGO, 26.95, 0.60, 4.72, 4.72 * 463 / 1351, "SMart ILIA — UMONS")

    # Section tabs, aligned on the same left margin as the body.
    for i, label in enumerate(SECTIONS):
        x = ML + i * 5.4
        box(label, x, 0.86, 4.9, 0.58, 12, R if i == section else M)
        if i == section:
            stem(x, 1.47, 4.9, 0.045)

    # Title zone: one baseline for every slide.
    box(title, ML, TITLE_Y, 24.3, TITLE_H, 29, INK, bold=True, name="Title")
    stem(ML, RULE_Y, 3.4, 0.07)

    slides.append({"title": title, "ops": ops, "notes": notes,
                   "seconds": seconds})


def caption(text, sub=None):
    """The fixed bottom band: hairline, takeaway, optional support line."""
    stem(ML, CAP_RULE_Y, CW, 0.03, LINE)
    box(text, ML, CAP_Y, CW, CAP_H, 21, R, bold=True, valign="top")
    if sub:
        box(sub, ML, SUB_Y, CW, SUB_H, 13.5, M, valign="top")


def footer():
    box("Project LANCE — NATO SPS G6259", ML, FOOT_Y, 14, 0.5, 10.5, M)
    box(f"{s}", RIGHT - 1.8, FOOT_Y, 1.8, 0.5, 10.5, M, align="right")


# ---------------------------------------------------------------- 1. Cover
page("", "Cover. Say: this is a progress report, not a results talk.",
     seconds=20, chrome=False)

stem(ML, 2.75, 0.14, 6.1)
box("LANCE", 3.35, 2.55, 22, 2.6, 52, INK, bold=True)
box("An autonomous and verifiable auditor\nfor IoT/IIoT networks",
    3.35, 5.35, 19.5, 2.1, 25, M)

stem(ML, 9.25, CW, 0.03, LINE)

box("Progress report — NATO SPS G6259", 3.35, 9.65, 20, 1.0, 18, R, bold=True)
box("23 October 2026  ·  Université de Mons, ILIA", 3.35, 10.75, 20, 0.8, 15, M)

panel(ML, 13.35, 11.6, 1.55, ROSE, ROSE)
stem(ML + 0.6, 13.95, 0.5, 0.14)
box("Status: work in progress.", ML + 1.2, 13.4, 10.2, 1.45, 14, M,
    italic=True)
picture(LOGO, 26.95, 1.40, 5.2, 5.2 * 463 / 1351, "SMart ILIA — UMONS")

# --------------------------------------------------------- 2. The objective
page("The objective",
     "One sentence on the left, three commitments on the right. Do not read "
     "the three rows aloud; they qualify the sentence, they do not repeat it. "
     "Close on the last line: training is not on the critical path.",
     seconds=60, sect=0)

box("An auditor that explores, identifies, verifies and reports.",
    TEXT_X, 5.40, TEXT_W, 4.2, 40, INK, bold=True, valign="top")
stem(TEXT_X, 10.10, 2.6, 0.10)

for i, (head, sub) in enumerate([
    ("Under which conditions", "rather than which model prevails"),
    ("Identical tools and budget", "for both approaches"),
    ("Evidence, not assertion", "recomputed from the log"),
]):
    y = 4.90 + i * 3.05
    panel(DIAG_X, y, DIAG_W, 2.55, GRAY, LINE, "rect")
    stem(DIAG_X, y + 0.55, 0.16, 1.45, R)
    box(head, DIAG_X + 0.85, y + 0.42, DIAG_W - 1.5, 0.95, 20, INK, bold=True)
    box(sub, DIAG_X + 0.85, y + 1.45, DIAG_W - 1.5, 0.75, 14, M)

caption("Model training is not a current priority.")
footer()

# ------------------------------------------------------- 3. The instrument
page("The instrument",
     "A chain, read top to bottom. Three pieces, three roles; the model sits "
     "inside the middle one. The last line is the methodological point: a run "
     "means nothing without a network whose truth is known.",
     seconds=50, sect=1)

roles = [
    ("Laboratory", "networks with known ground truth", GRAY, LINE, M),
    ("Platform", "conducts the audit", BLUE, B, B),
    ("Benchmark", "assesses the result", ROSE, R, R),
]
for i, (head, desc, fill, lc, accent) in enumerate(roles):
    y = 4.70 + i * 3.10
    panel(ML, y, CW, 2.88, fill, lc, "rect")
    stem(ML, y, 0.42, 2.88, accent)
    box(head, ML + 1.15, y, 8.2, 2.88, 23, accent if accent != M else INK,
        bold=True)
    box(desc, ML + 9.60, y, CW - 10.4, 2.88, 15, M)
    if i < 2:
        # Short, axis-aligned link in the accent column: a connector across
        # the gap would cut the box corners.
        stem(ML + 0.175, y + 2.88, 0.07, 0.22, accent)

caption("The model is one component among them.",
        "A run constitutes a measurement only against known ground truth.")
footer()

# ------------------------------------------------- 4. What counts as found
page("What constitutes a finding",
     "Two halves. Left: we recompute from the log, never from the conclusion. "
     "Right: the same trial runs on both configurations, so a false positive "
     "is visible. The bottom band is the second half of the rule.",
     seconds=80, sect=1)

PW = 14.2
panel(ML, 4.75, PW, 6.05, GRAY, LINE)
box("“I have read another organisation's data.”",
    ML + 0.7, 5.30, PW - 1.4, 1.9, 17, M, italic=True, align="center")
stem(ML + PW / 2 - 0.75, 7.70, 1.5, 0.05, LINE)
box("✕   Not admitted", ML + 0.7, 7.95, PW - 1.4, 1.5, 26, R, bold=True,
    align="center")

PX = RIGHT - PW
panel(PX, 4.75, PW, 6.05, ROSE, R)
box("The request and its response\ncontain the data.",
    PX + 0.7, 5.30, PW - 1.4, 1.9, 17, INK, align="center")
stem(PX + PW / 2 - 0.75, 7.70, 1.5, 0.05, R)
box("✓   Admitted", PX + 0.7, 7.95, PW - 1.4, 1.5, 26, GREEN, bold=True,
    align="center")

panel(ML, 11.55, CW, 2.45, BLUE, LINE)
stem(ML, 11.55, 0.14, 2.45, B)
box("The same trial is conducted on a healthy and on a vulnerable network.   "
    "A finding reported on the healthy one is recorded as an error.",
    ML + 1.0, 11.55, CW - 1.6, 2.45, 15, INK)

caption("The finding is recomputed from the log; the conclusion is never "
        "taken on trust.")
footer()

# ------------------------------------------------------- 5. Where we are
page("Current status",
     "Both approaches succeed everywhere. That is a property of the "
     "instrument, not a verdict on the model: the scale is saturated, so the "
     "bars carry no difference.",
     seconds=50, sect=2)

box("Both approaches succeed on every configuration.",
    ML, 4.42, 22.0, 1.85, 26, INK, bold=True, valign="top")
stem(ML, 6.25, 2.6, 0.10)

for i, (label, color) in enumerate([("Rule-based", M), ("Model-based", R)]):
    y = 7.05 + i * 3.55
    box(label, ML, y, 14.0, 0.85, 19, INK, bold=True)
    box("6 / 6", RIGHT - 5.0, y, 5.0, 0.85, 24, color, bold=True,
        align="right")
    # The bar is drawn to the full width of the scale: the saturation is the
    # finding, and it is the same on both rows.
    box("", ML, y + 1.05, CW, 1.65, fill=color)
    stem(ML, y + 2.70, CW, 0.03, LINE)

caption("The instrument does not discriminate between them.",
        "This is a limitation of the instrument, not of the model.")
footer()

# ----------------------------------------------------- 6. The register
page("The objective restated as hypotheses",
     "The objective does not change, its form does. Six network properties, "
     "six tests. H6 is detached on purpose: it is a risk, not a gain.",
     seconds=75, sect=2)

cards = [
    ("H1", "Connected devices", "a link absent from public inputs"),
    ("H2", "Heterogeneous formats", "a representation no parser covers"),
    ("H3", "Novel contracts", "rights stated in unseen documentation"),
    ("H4", "Vendor semantics", "a field whose meaning is only documented"),
    ("H5", "Ambiguous refusals", "resuming the audit after a refusal"),
    ("H6", "Hostile content", "an instruction obeyed from observed content"),
]
CARD_W = (CW - 2 * 0.63) / 3
for i, (code, prop, test) in enumerate(cards):
    col, row = i % 3, i // 3
    x = ML + col * (CARD_W + 0.63)
    y = 4.75 + row * 4.35
    h6 = code == "H6"
    panel(x, y, CARD_W, 3.95, ROSE if h6 else GRAY, R if h6 else LINE)
    box(code, x + 0.6, y + 0.38, 1.7, 0.85, 26, R if h6 else R, bold=True)
    box(prop, x + 2.35, y + 0.42, CARD_W - 2.9, 0.80, 15,
        R if h6 else INK, bold=True)
    stem(x + 0.6, y + 1.45, CARD_W - 1.2, 0.03, R if h6 else LINE)
    box(test, x + 0.6, y + 1.80, CARD_W - 1.2, 1.85, 14, M, valign="top")

caption("H1–H5 quantify a possible gain.      H6 quantifies a risk.")
footer()

# ------------------------------------------------------------- 7. V0
page("A control task before testing the model",
     "The gate is the condition of interpretation for everything else, and it "
     "binds both arms. Read the matrix by cells: the only cell that opens the "
     "register is the bottom right one.",
     seconds=70, sect=2)

box("A control task, simple enough to be solved without inference.   Both "
    "approaches are required to pass.",
    ML, 4.38, CW, 1.40, 17, M, valign="top")

HX, HW = 7.55, (RIGHT - 7.55 - 0.55) / 2
for j, lab in enumerate(["model ✗", "model ✓"]):
    box(lab, HX + j * (HW + 0.55), 5.92, HW, 0.58, 14, M, bold=True,
        align="center")

cells = [
    # row label, column index, verdict, colour, fill, accent
    (0, 0, "a defect in the instrument", R, ROSE, R),
    (0, 1, "a gain, or a coverage gap", INK, GRAY, LINE),
    (1, 0, "beyond the reach of this instrument", M, GRAY, LINE),
    (1, 1, "valid — the hypotheses may be read", GREEN, BLUE, GREEN),
]
for ri, (row, col, verdict, color, fill, accent) in enumerate(cells):
    y = 6.45 + row * 3.45
    x = HX + col * (HW + 0.55)
    panel(x, y, HW, 3.10, fill, R if fill == ROSE else LINE, "rect")
    stem(x, y, 0.14, 3.10, accent)
    box(verdict, x + 0.75, y, HW - 1.35, 3.10, 19, color, bold=(color != M))

for row, lab in enumerate(["script ✓", "script ✗"]):
    y = 6.45 + row * 3.45
    box(lab, ML, y, 4.85, 3.10, 17, M, bold=True, align="right")

caption("Only the fourth outcome permits the hypotheses to be read.",
        "Implemented and tested offline. The laboratory run remains outstanding.")
footer()

# ------------------------------------------------ 8. What we cannot claim
page("What we cannot claim",
     "Be explicit. This is the slide that buys credibility. Three limits, "
     "each stated as a claim we are not making, then the reason.",
     seconds=60, sect=3)

limits = [
    ("No general advantage", "No hypothesis has yet been executed."),
    ("No confidence interval",
     "Three repetitions yield a dispersion, not a sample."),
    ("No admitted evidence", "The metric definition is not frozen."),
]
for i, (head, body) in enumerate(limits):
    y = 4.80 + i * 3.05
    panel(ML, y, CW, 2.55, GRAY, LINE, "rect")
    stem(ML, y, 0.14, 2.55, R)
    box("✕", ML + 0.85, y, 1.1, 2.55, 22, R, bold=True)
    box(head, ML + 2.30, y, 9.4, 2.55, 20, R, bold=True)
    box(body, ML + 12.10, y, CW - 13.0, 2.55, 15, INK)

caption("A successful run is not a measurement: one early run reported "
        "success while every model arm had failed.")
footer()

# --------------------------------------------------------- 9. Next steps
page("Next steps",
     "Order follows conditions, not dates. Then the ask: vendor artifacts and "
     "an adversarial review of the register. Close on the deadline.",
     seconds=70, sect=3)

steps = [
    ("1", "Execute V0 on a held-out instance"),
    ("2", "Develop a parameterisable test harness"),
    ("3", "Build the scenario families for H2, H3 and H4"),
    ("4", "Deploy a reproducible platform"),
]
LW = cw(7)
for i, (num, head) in enumerate(steps):
    y = 5.00 + i * 2.40
    box(num, ML, y, 1.2, 1.55, 22, R, bold=True)
    box(head, ML + 1.95, y, LW - 2.0, 1.55, 20, INK)
    if i < len(steps) - 1:
        stem(ML + 1.95, y + 1.80, LW - 1.95, 0.03, LINE)

RX, RW = cx(8), cw(4)
panel(RX, 4.95, RW, 5.05, ROSE, ROSE)
stem(RX, 4.95, 0.14, 5.05, R)
box("Forms of support requested", RX + 0.85, 5.25, RW - 1.6, 0.85, 15, R,
    bold=True)
box("access to real vendor artifacts\n\nan adversarial review of the register",
    RX + 0.85, 6.20, RW - 1.6, 3.5, 16, INK, valign="top")

stem(RX, 10.70, RW, 0.03, LINE)
box("AsiaCCS 2027 — submission deadline\n11 December 2026 (AoE).",
    RX, 10.95, RW, 1.5, 13, M, valign="top")
footer()

# ----------------------------------------------------------- Reserve slide
page("Reserve — declared coverage gaps",
     "A benchmark that states its gaps is stronger than one that claims full "
     "coverage. One line each, no discussion unless asked.",
     seconds=0, sect=3)
gaps = ["Physical impact and functional safety",
        "Device fragility under probing",
        "Real fleet scale",
        "Proprietary industrial protocols that are not simulated",
        "Complete multi-step exploitation chains",
        "Abstention and calibration",
        "Generic IT scenarios, deliberately excluded"]
GW = (CW - 1.6) / 2
for i, g in enumerate(gaps):
    col = 0 if i < 4 else 1
    row = i if i < 4 else i - 4
    x = ML + col * (GW + 1.6)
    y = 5.10 + row * 2.55
    stem(x, y + 0.30, 0.55, 0.12, R)
    box(g, x + 1.05, y, GW - 1.1, 1.55, 16, INK, valign="top")
    stem(x, y + 1.85, GW, 0.03, LINE)
footer()

# ------------------------------------------------------------------ build
def run(args):
    p = subprocess.run(
        ["officecli", *map(str, args)],
        cwd=ROOT,
        env={**os.environ, "OFFICECLI_NO_AUTO_RESIDENT": "1"},
        text=True, capture_output=True,
    )
    if p.returncode or "UNSUPPORTED" in p.stdout + p.stderr:
        raise RuntimeError(p.stdout + p.stderr)
    return p.stdout


subprocess.run(["officecli", "close", str(FILE)], cwd=ROOT,
               text=True, capture_output=True)
run(["create", FILE, "--locale", "en-US", "--force"])
run(["set", FILE, "/",
     "--prop", "slideWidth=33.866667cm",
     "--prop", "slideHeight=19.05cm",
     "--prop", "author=Project LANCE"])

with tempfile.TemporaryDirectory() as tmp:
    for i, sl in enumerate(slides, 1):
        p = pathlib.Path(tmp) / f"batch-{i:02}.json"
        p.write_text(json.dumps(sl["ops"], ensure_ascii=False))
        run(["batch", FILE, "--input", p, "--json"])
        print(i, sl["title"] or "(cover)", flush=True)

run(["save", FILE])
print("written", FILE)
