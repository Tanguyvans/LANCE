"""Variante Opus — 2026-10-23 progress deck, rebuilt on an explicit grid.

Same content and same visual family as ../build.py (SMart ILIA / UMONS
template), but every slide is composed on one 12-column grid with a fixed
vertical structure: top bar / title zone / body zone / caption zone / footer.

Run:  python3 build.py
"""

import functools
import json
import os
import pathlib
import subprocess
import tempfile

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
CAP_Y, CAP_H = 14.88, 2.40        # holds two lines at CAP_SIZE
CAP_SIZE = 21                     # fixed: a caption that resizes is not a band
CAP_ADVANCE = 0.92                # line advance at CAP_SIZE, in cm
SUB_H = 0.50
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


def sized(text, x, y, w, h, size, color=INK, bold=False, align="left",
          valign="middle", italic=False, name=None):
    """Emit `text` at exactly `size`, bypassing fit_size.

    Lists and headings must hold one size across their items: routing them
    through fit_size lets the longest string shrink and leaves two sizes
    adjacent in the same list. Used only where the size has been checked
    against the box by hand.
    """
    add(
        "shape",
        name=name or f"Fixed-{len(ops)}",
        text=text,
        x=f"{x}cm", y=f"{y}cm", width=f"{w}cm", height=f"{h}cm",
        font=FONT, size=size, color=color, bold=bold, italic=italic,
        align=align, valign=valign, margin="0cm", fill="none", line="none",
        preset="rect", autoFit="none",
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
        sized(label, x, 0.80, 4.9, 0.75, 12, R if i == section else M)
        if i == section:
            stem(x, 1.47, 4.9, 0.045)

    # Title zone: one baseline for every slide.
    sized(title, ML, TITLE_Y, 24.3, TITLE_H, 29, INK, bold=True, name="Title")
    stem(ML, RULE_Y, 3.4, 0.07)

    slides.append({"title": title, "ops": ops, "notes": notes,
                   "seconds": seconds})


def caption(text, sub=None):
    """The fixed bottom band: hairline, takeaway, optional support line.

    The takeaway is set at CAP_SIZE regardless of length: `fit_size` would
    shrink a long caption below the 15 pt body it summarises and break the
    hierarchy. Length is handled by the band height instead.
    """
    stem(ML, CAP_RULE_Y, CW, 0.03, LINE)
    add(
        "shape",
        name=f"Caption-{s}",
        text=text,
        x=f"{ML}cm", y=f"{CAP_Y}cm", width=f"{CW}cm", height=f"{CAP_H}cm",
        font=FONT, size=CAP_SIZE, color=R, bold=True,
        align="left", valign="top", margin="0cm", fill="none", line="none",
        preset="rect", autoFit="none",
    )
    if sub:
        # The support line hangs directly under the takeaway, so it follows the
        # number of lines the takeaway actually takes.
        n = len(_wrap(text, (CW - 0.24) * CM / 1.18, CAP_SIZE, True))
        sized(sub, ML, CAP_Y + n * CAP_ADVANCE + 0.26, CW, 0.55, 13.5, M,
              valign="top")


def footer():
    sized("Project LANCE — NATO SPS G6259", ML, FOOT_Y, 14, 0.55, 10.5, M)
    sized(f"{s}", RIGHT - 1.8, FOOT_Y, 1.8, 0.55, 10.5, M, align="right")


# ---------------------------------------------------------------- 1. Cover
page("", "Cover. Say: this is a progress report, not a results talk.",
     seconds=20, chrome=False)

stem(ML, 2.75, 0.14, 6.1)
sized("LANCE", 3.35, 2.55, 22, 2.75, 46, INK, bold=True)
sized("An autonomous and verifiable auditor\nfor IoT/IIoT networks",
      3.35, 5.35, 19.5, 2.30, 25, M)

stem(ML, 9.25, CW, 0.03, LINE)

sized("Progress report — NATO SPS G6259", 3.35, 9.65, 20, 1.0, 18, R, bold=True)
sized("23 October 2026  ·  Université de Mons, ILIA", 3.35, 10.75, 20, 0.85, 15, M)

panel(ML, 13.30, 12.6, 1.60, ROSE, ROSE, "rect")
stem(ML, 13.30, 0.14, 1.60, R)
sized("Status: work in progress.", ML + 0.95, 13.30, 11.2, 1.60, 14, M,
      italic=True)
picture(LOGO, 26.95, 1.40, 5.2, 5.2 * 463 / 1351, "SMart ILIA — UMONS")

# --------------------------------------------------------- 2. The objective
page("The objective",
     "One sentence on the left, three commitments on the right. Do not read "
     "the three rows aloud; they qualify the sentence, they do not repeat it. "
     "Close on the last line.",
     seconds=60, sect=0)

sized("An auditor that explores, identifies, verifies and reports.",
      TEXT_X, 5.40, TEXT_W, 4.6, 25, INK, bold=True, valign="top")

for i, (head, sub) in enumerate([
    ("Under which conditions", "rather than which model prevails"),
    ("Identical tools and budget", "for both approaches"),
    ("Evidence, not assertion", "recomputed from the log"),
]):
    y = 4.90 + i * 3.05
    panel(DIAG_X, y, DIAG_W, 2.55, GRAY, LINE, "rect")
    stem(DIAG_X, y + 0.55, 0.16, 1.45, R)
    sized(head, DIAG_X + 0.85, y + 0.38, DIAG_W - 1.5, 1.05, 20, INK,
          bold=True)
    sized(sub, DIAG_X + 0.85, y + 1.48, DIAG_W - 1.5, 0.80, 14, M)

caption("Model training is not a current priority.")
footer()

# ------------------------------------------------------- 3. The instrument
page("The instrument",
     "Three pieces, three roles. The model is one piece among them. The last "
     "line is the methodological point: a run means nothing without a network "
     "whose truth is known.",
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
    # Head and description share one station across all three rows: the column
    # boundary is what makes this a table rather than two disconnected columns.
    sized(head, ML + 1.15, y, 6.0, 2.88, 23, accent if accent != M else INK,
          bold=True)
    sized(desc, ML + 7.55, y, CW - 8.35, 2.88, 15, M)
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

PW = cw(6)          # the counter-panels are a 6 + 6 split of the grid
panel(ML, 4.75, PW, 6.05, GRAY, LINE)
sized("“I have read another organisation's data.”",
      ML + 0.7, 5.22, PW - 1.4, 1.9, 16, M, italic=True, align="center")
stem(ML + PW / 2 - 0.75, 7.70, 1.5, 0.05, LINE)
sized("✕   Not admitted", ML + 0.7, 7.90, PW - 1.4, 1.6, 26, R, bold=True,
      align="center")

PX = RIGHT - PW
panel(PX, 4.75, PW, 6.05, ROSE, R)
sized("The request and its response\ncontain the data.",
      PX + 0.7, 5.22, PW - 1.4, 1.9, 16, INK, align="center")
stem(PX + PW / 2 - 0.75, 7.70, 1.5, 0.05, R)
sized("✓   Admitted", PX + 0.7, 7.90, PW - 1.4, 1.6, 26, GREEN, bold=True,
      align="center")

panel(ML, 11.55, CW, 2.45, BLUE, LINE, "rect")
stem(ML, 11.55, 0.14, 2.45, B)
sized("The same trial is conducted on a healthy and on a vulnerable network.   "
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

sized("Both approaches succeed on every configuration.",
      ML, BODY_Y, 26.6, 1.30, 26, INK, bold=True, valign="top")
stem(ML, 6.02, 2.6, 0.10)

for i, (label, color) in enumerate([("Rule-based", M), ("Model-based", R)]):
    y = 7.05 + i * 3.55
    sized(label, ML, y, 14.0, 1.10, 19, INK, bold=True)
    sized("6 / 6", RIGHT - 5.0, y - 0.10, 5.0, 1.30, 24, color, bold=True,
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
    # Square: the six cards are a table, like the cells on slide 7.
    panel(x, y, CARD_W, 3.95, ROSE if h6 else GRAY, R if h6 else LINE, "rect")
    # Code and title share one baseline; both are pinned, because the six
    # cards are a table and a table does not vary its type size per cell.
    sized(code, x + 0.6, y + 0.34, 1.7, 1.20, 20, R if h6 else INK, bold=True)
    sized(prop, x + 2.35, y + 0.56, CARD_W - 2.65, 0.80, 14,
          R if h6 else INK, bold=True)
    stem(x + 0.6, y + 1.62, CARD_W - 1.2, 0.03, R if h6 else LINE)
    sized(test, x + 0.6, y + 1.85, CARD_W - 1.2, 1.85, 14, M, valign="top")

caption("H1–H5 quantify a possible gain.      H6 quantifies a risk.")
footer()

# ------------------------------------------------------------- 7. V0
page("A control task before testing the model",
     "The gate is the condition of interpretation for everything else, and it "
     "binds both arms. Read the matrix by cells: the only cell that opens the "
     "register is the one where both arms pass — script check and model check.",
     seconds=70, sect=2)

sized("A control task, simple enough to be solved without inference.   Both "
      "approaches are required to pass.",
      ML, BODY_Y, CW, 1.45, 17, M, valign="top")

HX, HW = 7.55, (RIGHT - 7.55 - 0.55) / 2
for j, lab in enumerate(["model ✗", "model ✓"]):
    sized(lab, HX + j * (HW + 0.55), 5.98, HW, 0.80, 14, M, bold=True,
          align="center")

cells = [
    # row label, column index, verdict, colour, fill, accent
    # rows are `script`, columns are `model`
    (0, 0, "a defect in the instrument", R, ROSE, R),
    (0, 1, "valid — the hypotheses may be read", GREEN, BLUE, GREEN),
    (1, 0, "beyond the reach of this instrument", M, GRAY, LINE),
    (1, 1, "a gain, or a coverage gap", INK, GRAY, LINE),
]
for ri, (row, col, verdict, color, fill, accent) in enumerate(cells):
    y = 6.90 + row * 3.85
    x = HX + col * (HW + 0.55)
    panel(x, y, HW, 3.55, fill, R if fill == ROSE else LINE, "rect")
    stem(x, y, 0.14, 3.55, accent)
    box(verdict, x + 0.75, y, HW - 1.35, 3.55, 19, color, bold=(color != M))

for row, lab in enumerate(["script ✓", "script ✗"]):
    y = 6.90 + row * 3.85
    box(lab, ML, y, 4.85, 3.55, 17, M, bold=True, align="right")

caption("Only a control that the script and the model both pass permits the "
        "hypotheses to be read.",
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
LW = cx(8) - ML - 0.70        # up to the ask panel, less its gutter
for i, (num, head) in enumerate(steps):
    y = 4.95 + i * 2.60
    sized(num, ML, y, 1.2, 1.55, 22, R, bold=True)
    sized(head, ML + 1.95, y, LW - 1.95, 1.55, 20, INK)
    if i < len(steps) - 1:
        stem(ML + 1.95, y + 1.80, LW - 1.95, 0.03, LINE)

RX, RW = cx(8), cw(4)
panel(RX, 4.95, RW, 6.45, ROSE, ROSE, "rect")
stem(RX, 4.95, 0.14, 6.45, R)
sized("Support requested", RX + 0.85, 5.22, RW - 1.7, 0.95, 17, R, bold=True)
# Two parallel items, each on its own ruled row: the separator " · " cannot
# survive a wrap, so the parallel form is the separator.
for i, item in enumerate(["access to real vendor artifacts",
                          "an adversarial review of the register"]):
    y = 6.45 + i * 2.45
    stem(RX + 0.85, y + 0.40, 0.45, 0.11, R)
    sized(item, RX + 1.60, y, RW - 1.90, 2.10, 16, INK, valign="top")

caption("Order follows conditions, not dates.",
        "AsiaCCS 2027 — submission deadline 11 December 2026 (AoE).")
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
    # Left column: 4 rows on a 2.45 cm pitch. Right column: 3 rows on a pitch
    # that spans the same extent, so it is distributed, not dangling.
    y = 5.05 + row * (2.45 if col == 0 else 3.675)
    stem(x, y + 0.30, 0.55, 0.12, R)
    sized(g, x + 1.05, y, GW - 1.05, 2.00, 16, INK, valign="top")
    # No divider under the last row of a column: it would read as an empty cell.
    if row < (3 if col == 0 else 2):
        stem(x, y + 1.95, GW, 0.03, LINE)

caption("A benchmark that states its gaps is stronger than one that "
        "claims full coverage.")
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
