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

SECTIONS = ["Objective", "Method", "Control", "Hypotheses", "Next steps"]

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
        x = ML + i * 5.0
        sized(label, x, 0.80, 4.6, 0.75, 12, R if i == section else M)
        if i == section:
            stem(x, 1.47, 4.6, 0.045)

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


# ----------------------------------------------------------------- 1. Cover
page("", "Cover. Say: this is a progress report.", seconds=20, chrome=False)

stem(ML, 2.75, 0.14, 6.1)
sized("LANCE", 3.35, 2.55, 22, 2.75, 46, INK, bold=True)
sized("An autonomous and verifiable auditor\nfor IoT/IIoT networks",
      3.35, 5.35, 19.5, 2.30, 25, M)

stem(ML, 9.25, CW, 0.03, LINE)
sized("23 October 2026  ·  Université de Mons, ILIA", 3.35, 9.65, 20, 0.85,
      15, M)

picture(LOGO, 26.95, 1.40, 5.2, 5.2 * 463 / 1351, "SMart ILIA — UMONS")

# ------------------------------------------------------ 1. The objective
page("The objective",
     "Read the question aloud, then the three points. The question is about "
     "conditions, not about which model wins.",
     seconds=60, sect=0)

box("Under which conditions does an agentic approach prevail over a scripted "
    "one, rather than which model prevails?",
    ML, 4.90, CW, 3.40, 28, INK, bold=True, valign="top")

for i, text in enumerate([
    "An auditor that explores, identifies, verifies and reports.",
    "Identical tools and budget for both approaches, within the control harness.",
    "Evidence recomputed from the log, not asserted.",
]):
    y = 9.30 + i * 1.65
    stem(ML, y + 0.20, 0.14, 0.90, R)
    sized(text, ML + 0.55, y, CW - 0.55, 1.30, 18, INK, valign="middle")

caption("Model training is not a current priority.")
footer()

# ------------------------------------------------- 2. The platform in brief
page("The platform in brief",
     "The platform conducts the audit. Left: three facts. Right: the dashboard "
     "of a running instance. What the results mean comes later.",
     seconds=45, sect=0)

for i, text in enumerate([
    "Runs the audit in six phases",
    "Four execution modes",
    "Every run kept as evidence",
]):
    y = 5.40 + i * 2.30
    stem(TEXT_X, y + 0.25, 0.14, 1.20, R)
    sized(text, TEXT_X + 0.55, y, TEXT_W - 0.55, 1.70, 20, INK, bold=True,
          valign="middle")

PLAT_W = 16.0
picture(ROOT / "assets" / "platform-dashboard.jpg",
        RIGHT - PLAT_W, BODY_Y + 0.05, PLAT_W, PLAT_W / 1.6,
        "LANCE platform dashboard: network topology and run controls")

caption("The platform runs the audit; the benchmark judges it.",
        "Captures of the running instance, 22 October 2026.")
footer()

# ---------------------------------------- 3b. Script, LLM agent and harness
page("Script, LLM agent and harness",
     "The harness is fixed. Only the decision-maker changes: a script or an "
     "LLM agent, on the same tools, budget and log.",
     seconds=60, sect=1)

HY0, HH = 4.60, 9.70
panel(ML, HY0, CW, HH, BLUE, B, "rect")
sized("HARNESS  ·  same tools, budget, log and scoring for both",
      ML + 0.6, HY0 + 0.35, CW - 1.2, 0.8, 16, B, bold=True)

half = (CW - 1.2 - 0.6) / 2
for i, (head, body, accent) in enumerate([
    ("Script", "Fixed steps. No model.", M),
    ("LLM agent", "A model picks each next step.", R),
]):
    x = ML + 0.6 + i * (half + 0.6)
    panel(x, HY0 + 1.6, half, 2.6, "FFFFFF", accent, "rect")
    stem(x, HY0 + 1.6, half, 0.14, accent)
    sized(head, x + 0.6, HY0 + 2.1, half - 1.2, 0.9, 22,
          accent if accent != M else INK, bold=True)
    sized(body, x + 0.6, HY0 + 3.1, half - 1.2, 0.9, 16, INK, valign="top")
    stem(x + half / 2 - 0.025, HY0 + 4.2, 0.05, 0.7, accent)

panel(ML + 0.6, HY0 + 4.9, CW - 1.2, 1.2, GRAY, LINE, "rect")
sized("Same tools for both", ML + 1.0, HY0 + 4.9, CW - 2.0, 1.2, 18, INK,
      align="center")
stem(ML + CW / 2 - 0.025, HY0 + 6.1, 0.05, 0.5, B)
panel(ML + 0.6, HY0 + 6.6, CW - 1.2, 1.2, "FFFFFF", B, "rect")
sized("Same log, same scoring", ML + 1.0, HY0 + 6.6, CW - 2.0, 1.2, 18, INK,
      align="center")

caption("Only the decision-maker changes.")
footer()

# ------------------------------------------------- 3c. How a run is judged
page("How a run is judged against the goal",
     "Read left to right. The goal is set before the run. The scenario carries "
     "its own answer key. The benchmark compares what the platform reports "
     "with that key, never with the model's own conclusion.",
     seconds=60, sect=1)

steps = [
    ("Goal", "Find the weaknesses of a network, and only those"),
    ("Laboratory", "A scenario with planted weaknesses, listed in a "
                   "ground-truth file"),
    ("Platform", "Audits the scenario: six phases, one log per run"),
    ("Evidence", "Observations and proofs saved as files for each run"),
    ("Benchmark", "Compares findings with the truth: precision, recall, F1"),
]
GAP = 0.90
BW = (CW - 4 * GAP) / 5
FY, FH = 5.30, 5.00
for i, (head, body) in enumerate(steps):
    x = ML + i * (BW + GAP)
    accent = R if i == 4 else (B if i == 2 else M)
    fill = ROSE if i == 4 else (BLUE if i == 2 else GRAY)
    lc = R if i == 4 else (B if i == 2 else LINE)
    panel(x, FY, BW, FH, fill, lc, "rect")
    stem(x, FY, BW, 0.14, accent)
    sized(f"{i + 1}", x + 0.5, FY + 0.55, 2, 1.0, 16, accent, bold=True)
    sized(head, x + 0.5, FY + 1.35, BW - 1.0, 0.9, 20,
          accent if accent != M else INK, bold=True)
    sized(body, x + 0.5, FY + 2.20, BW - 1.0, 2.60, 13, M, valign="top")
    if i < 4:
        stem(x + BW + 0.08, FY + FH / 2 - 0.03, GAP - 0.16, 0.06, accent)

# Return path: the benchmark result loops back to the goal.
LY = FY + FH + 0.85
x0 = ML + BW / 2
x1 = ML + 4 * (BW + GAP) + BW / 2
stem(x0 - 0.025, FY + FH + 0.05, 0.05, LY - (FY + FH) - 0.05, R)
stem(x1 - 0.025, FY + FH + 0.05, 0.05, LY - (FY + FH) - 0.05, R)
stem(x0, LY, x1 - x0, 0.05, R)
sized("A result counts only against the planted truth; it never confirms the "
      "model's own conclusion.", ML, LY + 0.25, CW, 0.8, 16, R, bold=True,
      align="center")

caption("The score is computed against the planted truth, not against the "
        "platform's own conclusion.",
        "Precision, recall and F1 are recomputed from each run's log.")
footer()

# ------------------------------------------------- 4. What counts as found
page("What constitutes a finding",
     "A finding counts only once it is recomputed from the log. On the healthy "
     "network, any finding is an error.",
     seconds=60, sect=1)

PW = cw(6)          # two equal panels on the 6 + 6 split
PX = RIGHT - PW
PY, PH = 4.85, 7.20

panel(ML, PY, PW, PH, GRAY, LINE, "rect")
stem(ML, PY, PW, 0.14, R)
sized("Healthy network", ML + 0.8, PY + 0.7, PW - 1.6, 0.8, 14, M, bold=True)
sized("✕  Error", ML + 0.8, PY + 1.7, PW - 1.6, 1.4, 28, R, bold=True)
box("Any finding reported here is an error.",
    ML + 0.8, PY + 3.3, PW - 1.6, 2.0, 16, M, valign="top")

panel(PX, PY, PW, PH, BLUE, LINE, "rect")
stem(PX, PY, PW, 0.14, GREEN)
sized("Vulnerable network", PX + 0.8, PY + 0.7, PW - 1.6, 0.8, 14, M, bold=True)
sized("✓  Finding", PX + 0.8, PY + 1.7, PW - 1.6, 1.4, 28, GREEN, bold=True)
box("Recomputed from the log before it counts.",
    PX + 0.8, PY + 3.3, PW - 1.6, 2.0, 16, M, valign="top")

caption("The finding is recomputed from the log; the conclusion is never "
        "taken on trust.")
footer()

# ------------------------------------------------------------- 7. V0
page("A control task before testing the model",
     "V0 is the gate. Both arms face the same control task, and the hypotheses "
     "are read only if the script and the model both pass it.",
     seconds=70, sect=2)

sized("V0 is a control task, simple enough to be solved without inference. "
      "Both approaches must pass it.",
      ML, BODY_Y, CW, 1.45, 17, M, valign="top")

GY, GH = 7.20, 5.20
GW = cw(3)
for i, lab in enumerate(["Script passes", "Model passes"]):
    x = cx(3 * i)
    panel(x, GY, GW, GH, GRAY, LINE, "rect")
    stem(x, GY, GW, 0.14, M)
    sized(f"{i + 1}", x + 0.6, GY + 0.6, 2, 1.0, 16, M, bold=True)
    box(lab, x + 0.6, GY + 1.7, GW - 1.2, 2.0, 22, INK, bold=True,
        valign="top")

OX, OW = cx(6), cw(6)
panel(OX, GY, OW, GH, BLUE, LINE, "rect")
stem(OX, GY, OW, 0.14, GREEN)
sized("Both checks pass", OX + 0.8, GY + 0.6, OW - 1.6, 1.0, 16, M, bold=True)
box("Both pass: the hypotheses may be read.",
    OX + 0.8, GY + 1.7, OW - 1.6, 2.0, 24, GREEN, bold=True, valign="top")

caption("Only a control that both approaches pass permits the hypotheses to be "
        "read.",
        "Calibration passed on the lab network (3 of 3 runs per arm). The held-out instance remains outstanding.")
footer()

# ------------------------------------------- 3. The objective as hypotheses
page("The objective restated as hypotheses",
     "Six network properties, six tests. H1 to H5 test a possible gain; H6 is "
     "kept apart because it tests a risk.",
     seconds=75, sect=3)

sized("The register is this list: each hypothesis, with the test that decides it.",
      ML, 4.45, CW, 0.90, 16, M, valign="top")

hypotheses = [
    ("H1", "Connected devices", "a link absent from public inputs"),
    ("H2", "Heterogeneous formats", "a representation no parser covers"),
    ("H3", "Novel contracts", "rights stated in unseen documentation"),
    ("H4", "Vendor semantics", "a field whose meaning is only documented"),
    ("H5", "Ambiguous refusals", "resuming the audit after a refusal"),
    ("H6", "Hostile content", "an instruction obeyed from observed content"),
]
COL_NAME, COL_TEST = ML + 2.0, ML + 11.2
for i, (code, name, test) in enumerate(hypotheses):
    y = 5.80 + i * 1.40
    h6 = code == "H6"
    colour = R if h6 else INK
    sized(code, ML, y, 1.7, 1.20, 18, colour, bold=True)
    sized(name, COL_NAME, y, COL_TEST - COL_NAME - 0.3, 1.20, 18, colour,
          bold=True)
    sized(test, COL_TEST, y, CW - (COL_TEST - ML), 1.20, 16, M)
    stem(ML, y + 1.28, CW, 0.03, LINE)

caption("H1–H5 quantify a possible gain. H6 quantifies a risk.")
footer()

# ------------------------------------------------------- 4. Next steps
page("Next steps",
     "Order follows conditions, not dates. Then the request: vendor artifacts "
     "and an adversarial review of the register.",
     seconds=70, sect=4)

steps = [
    ("1", "Execute V0 on a held-out instance"),
    ("2", "Develop a parameterisable test harness"),
    ("3", "Build the scenario families for H2, H3 and H4"),
    ("4", "Deploy a reproducible platform"),
]
LW = cx(8) - ML - 0.70        # up to the request panel, less its gutter
for i, (num, text) in enumerate(steps):
    y = 4.95 + i * 2.40
    sized(num, ML, y, 1.2, 1.40, 22, R, bold=True)
    sized(text, ML + 1.95, y, LW - 1.95, 1.70, 20, INK)

RX, RW = cx(8), cw(4)
panel(RX, 4.95, RW, 6.45, ROSE, ROSE, "rect")
stem(RX, 4.95, 0.14, 6.45, R)
sized("Support requested", RX + 0.85, 5.22, RW - 1.7, 0.95, 17, R, bold=True)
for i, item in enumerate(["Access to real vendor artifacts",
                          "An adversarial review of the register"]):
    y = 6.45 + i * 2.45
    stem(RX + 0.85, y + 0.40, 0.45, 0.11, R)
    sized(item, RX + 1.60, y, RW - 1.90, 2.10, 16, INK, valign="top")

caption("Order follows conditions, not dates.",
        "Support line: AsiaCCS 2027 submission, 11 December 2026 (AoE).")
footer()

# ----------------------------------------------------------- Reserve slide
page("Reserve — declared coverage gaps",
     "A benchmark that states its gaps is stronger than one that claims full "
     "coverage. One line each, no discussion unless asked.",
     seconds=0, sect=4)
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
