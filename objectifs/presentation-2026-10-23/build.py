"""Build the 2026-10-23 progress deck as a PPTX.

Visual grammar taken from the committee deck template: white background, section
tabs in the top bar, SMart ILIA logo, crimson accent, pale rose / blue panels.
Slide canvas is 33.87 x 19.05 cm (16:9).

Run:  python3 build.py
"""

import csv
import functools
import io
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
    fontScale, so the size has to be right in the document itself.
    """
    if not text:
        return size
    # The headless renderer substitutes a wider fallback face for Arial, so
    # both the measured width and the line height are inflated on purpose.
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
ORANGE = "D97721"
FONT = "Arial"

SECTIONS = ["Objective", "Instrument", "Hypotheses", "Outlook"]

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


def node(name, text, x, y, w, h, fill=GRAY, color=INK, line_color=LINE, size=17):
    box(text, x, y, w, h, size, color, fill, True, "center", name,
        f"{line_color}:1pt", "roundRect", "0.18cm")


def arrow(a, b, color=M, width=1.8, dashed=False, kind="straight"):
    props = {
        "from": f"/slide[{s}]/shape[@name={a}]",
        "to": f"/slide[{s}]/shape[@name={b}]",
        "color": color, "tailEnd": "triangle",
        "lineWidth": f"{width}pt", "shape": kind,
    }
    if dashed:
        # officecli's connector schema has no dashStyle; draw a thinner arrow.
        props["lineWidth"] = "1.2pt"
    add("connector", **props)


def picture(path, x, y, w, h, alt=""):
    add("picture", src=str(path), x=f"{x}cm", y=f"{y}cm",
        width=f"{w}cm", height=f"{h}cm", alt=alt)


def page(title, notes="", seconds=60, sect=None, chrome=True):
    """Start a slide: blank canvas, title, logo, footer, section tabs.

    `chrome=False` is for the cover, which carries its own layout and must not
    repeat the logo or the footer.
    """
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

    picture(LOGO, 27.2, 0.62, 4.7, 4.7 * 463 / 1351, "SMart ILIA — UMONS")
    box(title, 1.8, 1.75, 24.8, 1.9, 29, INK, bold=True, name="Title")
    box("", 1.8, 3.95, 3.4, 0.06, fill=R)  # crimson rule under the title

    # Top section tabs.
    for i, label in enumerate(SECTIONS):
        x = 1.8 + i * 5.6
        box(label, x, 0.85, 5.0, 0.62, 12,
            R if i == section else M)
        if i == section:
            box("", x, 1.5, 5.0, 0.045, fill=R)

    # Footer.
    box("Project LANCE — NATO SPS G6259", 1.8, 17.5, 14, 0.55, 10.5, M)
    box(f"{s}", 30.6, 17.5, 1.4, 0.55, 10.5, M, align="right")

    slides.append({"title": title, "ops": ops, "notes": notes,
                   "seconds": seconds})


def table(rows, x, y, w, h, widths=None, size=15, header_color=R):
    ti = 1 + sum(o.get("type") == "table" for o in ops)
    stream = io.StringIO()
    csv.writer(stream, lineterminator=";").writerows(rows)
    props = dict(
        data=stream.getvalue().rstrip(";"),
        x=f"{x}cm", y=f"{y}cm", width=f"{w}cm", height=f"{h}cm",
        style="none", headerFill="FFFFFF", bodyFill="FFFFFF", firstRow=True,
        **{"border.all": "none", "border.horizontal": "0.6pt solid D9DEE5"},
    )
    if widths:
        props["colWidths"] = ",".join(f"{v}cm" for v in widths)
    add("table", **props)
    for ri, row in enumerate(rows, 1):
        for ci, _ in enumerate(row, 1):
            command("set", path=f"/slide[{s}]/table[{ti}]/tr[{ri}]/tc[{ci}]",
                    props={"font": FONT, "size": str(size),
                           "color": header_color if ri == 1 else INK,
                           "bold": str(ri == 1).lower(),
                           "align": "left", "valign": "center",
                           "padding": "0.16cm"})


# ---------------------------------------------------------------- 1. Cover
page("", "Cover. Say: this is a progress report, not a results talk.",
     seconds=20, chrome=False)
box("", 2.0, 4.4, 0.14, 8.4, fill=R)
box("LANCE", 3.4, 3.9, 26, 2.2, 52, INK, bold=True)
box("An autonomous, provable auditor\nfor IoT/IIoT networks", 3.4, 6.4, 26, 2.4,
    25, M)
box("Progress report — NATO SPS G6259", 3.4, 10.4, 26, 1.0, 18, R, bold=True)
box("23 October 2026  ·  Université de Mons, ILIA", 3.4, 11.4, 26, 0.9, 15, M)
box("Work in progress: no general advantage of the model is demonstrated.",
    3.4, 13.6, 26, 0.9, 13, M, italic=True)
picture(LOGO, 26.9, 1.4, 5.2, 5.2 * 463 / 1351, "SMart ILIA — UMONS")

# --------------------------------------------------------- 2. The objective
page("The objective, and what it implies",
     "The objective commits us to three things. Say them in order: conditions "
     "rather than ranking, parity of tools, verifiable not plausible.",
     seconds=75, sect=0)

node("obj", "An autonomous and provable auditor\nfor IoT/IIoT networks",
     8.4, 4.9, 17.0, 2.6, ROSE, R, R, 20)
box("explores · finds · verifies · reports · with recomputable evidence",
    8.4, 7.5, 17.0, 1.2, 15, M, align="center")

# A distribution bus: one stem from the objective, then one drop per branch.
box("", 16.85, 8.9, 0.06, 0.5, fill=R)
box("", 2.0, 9.4, 29.8, 0.06, fill=R, name="bus")
node("c1", "Which conditions?\nnot “which model wins”", 2.0, 9.9, 9.2, 2.4,
     GRAY, INK)
node("c2", "Parity of tools,\ninputs and budgets", 12.3, 9.9, 9.2, 2.4,
     GRAY, INK)
node("c3", "Conclusions that are\nverifiable, not plausible", 22.6, 9.9, 9.2,
     2.4, GRAY, INK)
for cx in (6.6, 16.9, 27.2):  # the three drop points, drawn as stems
    box("", cx - 0.045, 9.44, 0.09, 0.52, fill=R)

box("Current priorities", 2.0, 13.6, 14, 0.55, 13, R, bold=True)
node("p1", "1. Benchmark — the instrument that answers the question",
     2.0, 14.3, 14.6, 1.5, BLUE, B, B, 14)
node("p2", "2. Platform — deploy, launch, follow, retrieve, isolate, clean up",
     17.4, 14.3, 14.6, 1.5, BLUE, B, B, 14)
box("Out of priority: model training. The paper reports what the benchmark "
    "measures; it does not drive the order of work.",
    2.0, 16.1, 30.0, 0.9, 12, M)

# ------------------------------------------------------- 3. Three pieces
page("How we answer it: three pieces, three roles",
     "The laboratory reconstructs known networks; the platform runs the audit; "
     "the benchmark is what turns a run into a measurement. The model is only "
     "one piece.", seconds=55, sect=1)

node("lab", "Laboratory", 2.4, 5.6, 8.4, 1.5, GRAY, INK, M, 20)
box("networks we already know,\nwith private ground truth",
    2.4, 7.15, 8.4, 1.4, 13, M, align="center")

node("plat", "Platform", 12.7, 5.6, 8.4, 1.5, BLUE, B, B, 20)
box("runs the audit,\nreturns the result", 12.7, 7.15, 8.4, 1.4, 13, M,
    align="center")

node("bench", "Benchmark", 23.0, 5.6, 8.4, 1.5, ROSE, R, R, 20)
box("confronts the result\nto the ground truth", 23.0, 7.15, 8.4, 1.4, 13, M,
    align="center")

arrow("lab", "plat", M, 2.2)
arrow("plat", "bench", M, 2.2)

# The six-phase pipeline, with the model as one phase among six.
box("Inside the platform: six phases, one shared record", 2.4, 9.6, 20, 0.55,
    13, R, bold=True)
phases = [
    ("Map", "what is there"),
    ("Triage", "what looks wrong"),
    ("Verify", "what is proven"),
    ("Intrude", "what is reachable"),
    ("Report", "what is said"),
]
w, gap = 4.9, 0.72
for i, (t, d) in enumerate(phases):
    x = 2.4 + i * (w + gap)
    node(f"ph{i}", f"{i + 1}. {t}", x, 10.4, w, 1.2, GRAY, INK, LINE, 14)
    box(d, x, 11.65, w, 0.8, 11, M, align="center")
    if i < len(phases) - 1:
        box("›", x + w + 0.1, 10.9, 0.5, 0.6, 18, M, bold=True, align="center")

node("eq", "A shared record every phase reads and enriches",
     2.4, 12.9, 12.6, 1.25, ROSE, R, R, 12)
node("mdl", "The model proposes; it never records or verifies",
     15.8, 12.9, 15.8, 1.25, ROSE, R, R, 12)
box("No phase substitutes for another; the model is one contributor among "
    "them.", 2.4, 14.7, 29.2, 0.9, 14, R, bold=True, align="center")
box("A run is not a measurement until the benchmark confronts it to a known "
    "ground truth.", 2.4, 15.7, 29.2, 0.8, 12.5, M, align="center")

# ------------------------------------------------- 4. What counts as found
page("What counts as “found”",
     "Two halves. Left: we recompute from the log, never from the conclusion. "
     "Right: the same trial runs on both configurations, so a false positive "
     "is visible.", seconds=80, sect=1)

node("claim", "“I read the data of another organisation.”", 2.2, 4.9, 14.2, 1.5,
     GRAY, M, LINE, 14)
box("✕", 2.9, 6.6, 1.2, 1.2, 30, R, bold=True)
box("Claimed only — not counted", 4.4, 6.6, 11.0, 1.2, 15, M)

node("evid", "The logged request and\nits response contain the data.", 2.2, 8.4,
     14.2, 1.7, GRAY, INK, LINE, 14)
box("✓", 2.9, 10.3, 1.2, 1.2, 30, GREEN, bold=True)
box("Recomputed from the tool log — counted", 4.4, 10.3, 11.0, 1.2, 15, INK)

box("We recompute the finding from the tool log.\nWe do not re-run the "
    "requests, and we never trust the conclusion.",
    2.2, 12.3, 14.2, 1.6, 14, R, bold=True)

# Right: the two configurations.
box("The trap: two configurations of the same network", 18.0, 4.9, 14.4, 0.8,
    14, R, bold=True)
node("cfg0", "Configuration A\nthe tested weakness is absent", 18.0, 5.9, 6.9, 2.2,
     BLUE, B, B, 13)
node("cfg1", "Configuration B\nthe tested weakness is present", 25.5, 5.9, 6.9, 2.2,
     ROSE, R, R, 13)

box("Correct answer:\n“nothing to report”", 18.0, 8.3, 6.9, 1.3, 13, M,
    align="center")
box("Correct answer:\n“found, with proof”", 25.5, 8.3, 6.9, 1.3, 13, M,
    align="center")

box("Finding something in A is a false positive — counted as an error.",
    18.0, 10.1, 14.4, 1.0, 14, R, bold=True)
node("both", "A good auditor succeeds on both", 18.0, 11.6, 14.4, 1.6, ROSE, R, R,
     18)
box("That single rule is what makes an audit measurable instead of "
    "believable.", 18.0, 13.5, 14.4, 1.0, 13, M)

# --------------------------------------------------- 5. First campaign
page("What the first campaign showed",
     "Both arms succeed everywhere. That is a property of the instrument, not "
     "a verdict on the model. Do not say the model is useless.", seconds=70,
     sect=2)

box("Two network families · two configurations each · three repetitions",
    2.2, 4.9, 29.0, 0.8, 15, M)

# A saturation plot: the two bars are the whole story.
box("", 2.2, 6.0, 16.4, 5.6, fill=GRAY, preset="roundRect", line=f"{LINE}:1pt")
box("Trials succeeded, out of six", 2.7, 6.2, 15.4, 0.6, 12, M, bold=True)
for i, (label, color) in enumerate([("Rules", M), ("Model", R)]):
    y = 7.1 + i * 2.05
    box(label, 2.7, y, 2.6, 0.9, 13, INK, bold=True)
    box("", 5.5, y + 0.1, 10.6, 0.7, fill=color)  # full: the scale saturates
    box("6 / 6", 16.4, y, 1.7, 0.9, 14, color, bold=True, align="center")
box("Both bars are full, on every family and every repetition.",
    2.7, 10.9, 15.4, 0.6, 12, M)

node("verdict", "The instrument is saturated", 20.4, 6.0, 11.2, 1.6, ROSE, R, R,
     19)
box("It cannot separate the two approaches — and separating them is exactly "
    "what a benchmark must do.", 20.4, 7.8, 11.2, 1.5, 12.5, INK)
box("This is not a failure of the model.\nIt is a failure of the instrument: "
    "a set of scenarios passed by everyone tests no competence.",
    20.4, 9.5, 11.2, 2.1, 12, R, bold=True)

box("What it means", 2.2, 12.3, 13.8, 0.6, 13, R, bold=True)
box("• not “the model is better” — there is no difference\n"
    "• not “the model is useless” — the pilot was built to qualify the\n"
    "   instrument, not to decide between the arms",
    2.2, 12.9, 14.0, 2.0, 12, INK)
box("What it does not mean", 17.6, 12.3, 13.8, 0.6, 13, R, bold=True)
box("It cannot decide between the arms. What it does establish is that both "
    "instruments measure at all — which is the precondition for the register "
    "to be worth running.", 17.6, 12.9, 14.0, 2.0, 12, M)

# ----------------------------------------------------- 6. The register
page("So the objective is restated as hypotheses",
     "The objective does not change, its form does. Six properties, six "
     "tests. H6 is a risk, not a gain.", seconds=90, sect=2)

box("“Is the model better?” cannot be settled.  "
    "“Which properties of a network make a model add something — and which do "
    "not?” can.", 2.2, 4.6, 29.0, 1.1, 15, INK)

cards = [
    ("H1", "Devices are connected", "an identity link absent from public inputs"),
    ("H2", "Formats are heterogeneous", "a format the declared parsers do not cover"),
    ("H3", "Contracts are unseen", "rights and goals from never-seen documentation"),
    ("H4", "Meaning is vendor-specific", "a field whose sense is only in naming or doc"),
    ("H5", "Devices refuse", "resuming beyond the script's standard branch"),
    ("H6", "Content is hostile", "whether a planted instruction is obeyed"),
]
for i, (code, prop, test) in enumerate(cards):
    col, row = i % 3, i // 3
    x = 2.2 + col * 9.9
    y = 6.0 + row * 4.4
    fill, accent = (ROSE, R) if code == "H6" else (GRAY, INK)
    box("", x, y, 9.3, 3.9, fill=fill, preset="roundRect", line=f"{LINE}:1pt")
    box(code, x + 0.5, y + 0.35, 1.8, 0.9, 22, accent, bold=True)
    box(prop, x + 2.4, y + 0.35, 6.4, 0.9, 14, accent, bold=True)
    box(test, x + 0.5, y + 1.45, 8.3, 2.1, 12, M)

box("H1–H5 measure a possible gain.   H6 measures a risk: we predict that a "
    "model obeys an injected instruction while a script ignores it — zero "
    "compliance is the good outcome.",
    2.2, 15.2, 29.0, 1.3, 13, R, bold=True)

# ------------------------------------------------------------- 7. V0
page("Before testing the model, test the test",
     "V0 is the condition of interpretation for everything else. It is a gate "
     "on both arms. The briefing failure is the concrete example.", seconds=75,
     sect=2)

node("v0", "Control task\nsolvable without inference", 2.2, 4.9, 12.0, 1.9, ROSE,
     R, R, 15)
box("Both approaches must pass, above a threshold frozen after the first "
    "pilot.", 2.2, 6.9, 12.0, 1.0, 11.5, M)

box("What it already caught", 2.2, 8.6, 12.0, 0.6, 13, R, bold=True)
box("A briefing documented no HTTP route. The model tried paths outside the "
    "contract and collected 404s, while the script knew where to read the "
    "policy. The defect was in the harness.",
    2.2, 9.2, 12.4, 2.1, 11.5, INK)
node("green", "A green run would have said nothing", 2.2, 11.5, 12.4, 1.2,
     ROSE, R, R, 13)

# The gate, drawn as four outcomes of one decision.
box("The four outcomes of the gate", 16.6, 4.5, 14.4, 0.6, 13, R, bold=True)
rows = [
    ("script ✓  model ✗", "instrument defect, not a matter of competence",
     R, ROSE),
    ("script ✗  model ✓", "either a gain, or a coverage gap to requalify",
     INK, GRAY),
    ("script ✗  model ✗", "out of reach for this instrument", M, GRAY),
    ("script ✓  model ✓", "valid control — interpret the hypotheses", GREEN,
     BLUE),
]
for i, (arm, verdict, color, fill) in enumerate(rows):
    y = 5.25 + i * 1.62
    box("", 16.6, y, 14.4, 1.42, fill=fill, preset="roundRect",
        line=f"{LINE}:1pt")
    box(arm, 17.0, y + 0.12, 5.5, 1.18, 12.5, color, bold=True)
    box(verdict, 22.7, y + 0.12, 8.2, 1.18, 11.5, color)

box("Both arms, four outcomes — and only the last one licenses reading the "
    "six hypotheses.", 2.2, 13.2, 29.0, 0.9, 13, R, bold=True, align="center")

box("Status: the control is written and tested offline. The laboratory run on "
    "a held-out instance remains to be done — MQTT as it stands; SSH only "
    "after the dictionary is randomised.",
    2.2, 14.4, 29.0, 1.1, 12, M)

# ------------------------------------------------- 8. What we measure
page("What we can measure today",
     "Three descriptive measurements. Not the results of the six hypotheses. "
     "The third one is coverage, not intelligence.", seconds=85, sect=3)

box("All three are descriptive. None is a result of the six hypotheses.",
    2.2, 4.7, 29.0, 0.8, 14, R, bold=True)

# KPI tiles
node("k1", "2 models", 2.2, 5.9, 6.6, 1.4, BLUE, B, B, 18)
box("both succeed on both families", 2.2, 7.35, 6.6, 0.9, 12, M, align="center")
box("≈ 2× cost\n1.3–1.7× time", 2.2, 8.4, 6.6, 1.6, 16, INK, bold=True,
    align="center")

node("k2", "Variability", 10.2, 5.9, 6.6, 1.4, BLUE, B, B, 18)
box("6 % – 46 %\nacross repetitions", 10.2, 7.35, 6.6, 1.8, 16, INK,
    bold=True, align="center")
# A 0–50 % track, with the observed span drawn on it.
box("", 10.5, 9.4, 6.0, 0.16, fill=LINE)
box("", 10.5 + 6.0 * 0.06 / 0.5, 9.4, 6.0 * (0.46 - 0.06) / 0.5, 0.16, fill=R)
box("6 %", 10.2, 9.7, 1.4, 0.6, 10, M, align="center")
box("46 %", 15.6, 9.7, 1.4, 0.6, 10, M, align="center")
box("one cold model load excluded", 10.2, 10.35, 6.6, 0.7, 10.5, M,
    align="center")

node("k3", "1 discriminating case", 18.2, 5.9, 6.6, 1.4, ROSE, R, R, 18)
box("access control\nbetween organisations", 18.2, 7.35, 6.6, 1.6, 14, INK,
    align="center")
box("one repetition, not admitted", 18.2, 9.15, 6.6, 0.8, 12, M, align="center")

node("k4", "3 repetitions", 26.2, 5.9, 5.4, 1.4, GRAY, INK, LINE, 18)
box("a dispersion,\nnot a sample", 26.2, 7.35, 5.4, 1.6, 13, M, align="center")

# Comparison strip
box("The discriminating case", 2.2, 10.6, 29.0, 0.6, 13, R, bold=True)
node("sc", "Scripted comparator", 2.2, 11.3, 9.4, 1.3, GRAY, INK, LINE, 14)
node("md", "Model", 12.6, 11.3, 9.4, 1.3, GRAY, INK, LINE, 14)
node("bd", "Boundary", 23.0, 11.3, 8.2, 1.3, ROSE, R, R, 14)
box("stops at the object boundary\ndeclared in advance",
    2.2, 12.7, 9.4, 1.3, 12, M)
box("follows the published policy\nand crosses that boundary",
    12.6, 12.7, 9.4, 1.3, 12, M)
box("the script never inspects it", 23.0, 12.7, 8.2, 1.3, 12, R)

box("That is coverage, not intelligence.", 2.2, 14.3, 29.0, 1.0, 20, R,
    bold=True, align="center")
box("The script is deliberately built to stop where it stops. The comparison "
    "measures the declared limit of the baseline, not a capability gap.",
    2.2, 15.4, 29.0, 1.0, 13, M, align="center")

# ------------------------------------------------ 9. What we cannot claim
page("What we cannot claim",
     "Be explicit. This is the slide that buys credibility. Four limits.",
     seconds=60, sect=3)

limits = [
    ("No general advantage", "No hypothesis of the register has been executed "
     "yet. A measured gain is still ahead."),
    ("No confidence interval", "One family per harness. Three repetitions give "
     "a dispersion, not statistical inference."),
    ("Nothing admitted", "The metric definition is not frozen, so no campaign "
     "can serve as confirmatory evidence."),
    ("No measured cost", "Neither billed nor hardware cost. Tariff estimates "
     "are not a monetary measurement."),
]
for i, (head, body) in enumerate(limits):
    x = 2.2 + (i % 2) * 14.9
    y = 5.2 + (i // 2) * 4.6
    box("", x, y, 14.2, 4.0, fill=GRAY, preset="roundRect", line=f"{LINE}:1pt")
    box("✕", x + 0.6, y + 0.45, 1.2, 1.0, 22, R, bold=True)
    box(head, x + 2.0, y + 0.45, 11.4, 1.0, 17, R, bold=True)
    box(body, x + 0.6, y + 1.6, 13.0, 2.1, 13, INK)

box("And one lesson we keep: a “green run” is not an exploitable measurement — "
    "an early run was green while every model arm had failed.",
    2.2, 14.9, 29.0, 1.2, 13, M, align="center")

# --------------------------------------------------------- 10. Next steps
page("Next steps, and what would help",
     "Order follows conditions, not dates. Only external constraint is the "
     "submission. End by naming the two things that would help.", seconds=70,
     sect=3)

steps = [
    ("1", "V0 on a held-out instance",
     "MQTT as it stands; SSH after the dictionary is randomised"),
    ("2", "A parameterisable harness",
     "today one scenario is a locked module; adding a family duplicates code"),
    ("3", "Families for H2, H3, H4",
     "private ground truth, declared baseline, evaluator"),
    ("4", "The platform",
     "reproducible deployment, launch, follow-up, retrieval"),
]
for i, (num, head, body) in enumerate(steps):
    y = 4.9 + i * 2.45
    box(num, 2.2, y + 0.25, 1.4, 1.2, 24, R, bold=True)
    box(head, 3.9, y, 12.4, 0.9, 17, INK, bold=True)
    box(body, 3.9, y + 0.85, 12.4, 0.9, 12, M)
    if i < len(steps) - 1:
        box("", 2.87, y + 1.5, 0.06, 1.0, fill=LINE)

box("", 18.0, 4.9, 14.6, 5.8, fill=ROSE, preset="roundRect")
box("What would help most", 18.6, 5.2, 13.4, 0.7, 15, R, bold=True)
box("• real vendor artifacts — H2 and H4 lack a corpus\n"
    "• an adversarial review of the register, on falsifiability grounds",
    18.6, 6.1, 13.4, 2.4, 13, INK)

box("", 18.0, 11.0, 14.6, 3.4, fill=GRAY, preset="roundRect")
box("Single external constraint", 18.6, 11.3, 13.4, 0.7, 15, R, bold=True)
box("AsiaCCS 2027, 11 December 2026 (AoE).\nIt does not order the steps, and "
    "justifies neither an unvalidated scope nor an unmeasured result.",
    18.6, 12.1, 13.4, 2.1, 13, INK)

box("The measure is now the hypothesis register, not the scenario count.",
    2.2, 15.3, 29.0, 1.0, 17, R, bold=True, align="center")

# ------------------------------------------------------ Reserve slides
page("Reserve — model panel",
     "Only if asked. Costs are tariff estimates, not billed measurements.",
     seconds=0, sect=3)
table(
    [["Family", "Approach", "Success", "Cost ($)"],
     ["SSH", "rules", "6/6", "0"],
     ["SSH", "dense model", "6/6", "0.006–0.008"],
     ["SSH", "MoE model", "6/6", "0.012–0.017"],
     ["MQTT", "rules", "6/6", "0"],
     ["MQTT", "dense model", "6/6", "0.004–0.010"],
     ["MQTT", "MoE model", "6/6", "0.012–0.016"]],
    2.2, 5.6, 29.0, 7.4, widths=[8, 9, 5, 7])
box("Each family is a distinct configuration: the two are never pooled.",
    2.2, 13.6, 29.0, 0.9, 13, M)

page("Reserve — variability",
     "Coefficient of variation over three repetitions. The 92 % figure is one "
     "cold model load, not policy variability.", seconds=0, sect=3)
table(
    [["Family / configuration", "Duration", "Cost", "Tokens"],
     ["SSH, weakness absent", "92.3 %", "7.0 %", "5.9 %"],
     ["SSH, weakness present", "6.4 %", "17.9 %", "21.8 %"],
     ["MQTT, weakness absent", "27.8 %", "46.1 %", "25.6 %"],
     ["MQTT, weakness present", "10.2 %", "34.7 %", "35.6 %"]],
    2.2, 5.6, 29.0, 6.2, widths=[13, 5.3, 5.3, 5.4])
box("The 92 % comes from a cold model load (73.7 s against 16.6 and 16.7 s), "
    "not from policy variability.", 2.2, 12.2, 29.0, 0.9, 13, M)

page("Reserve — declared coverage gaps",
     "A benchmark that states its gaps is stronger than one that claims full "
     "coverage.", seconds=0, sect=3)
gaps = ["Physical impact and functional safety",
        "Device fragility under probing",
        "Real fleet scale",
        "Proprietary industrial protocols that are not simulated",
        "Complete multi-step exploitation chains",
        "Abstention and calibration",
        "Generic IT scenarios, deliberately excluded"]
for i, g in enumerate(gaps):
    y = 5.0 + i * 1.45
    box("—", 2.2, y, 1.0, 0.9, 16, R, bold=True)
    box(g, 3.4, y, 27.0, 0.9, 15, INK)

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


run(["create", FILE, "--locale", "en-US", "--force"])
run(["set", FILE, "/",
     "--prop", "slideWidth=33.866667cm",
     "--prop", "slideHeight=19.05cm",
     "--prop", "author=Project LANCE"])

# The batch files are scratch input for officecli, generated at each run:
# they go in a temporary directory rather than beside the deck.
with tempfile.TemporaryDirectory() as tmp:
    for i, sl in enumerate(slides, 1):
        p = pathlib.Path(tmp) / f"batch-{i:02}.json"
        p.write_text(json.dumps(sl["ops"], ensure_ascii=False))
        run(["batch", FILE, "--input", p, "--json"])
        print(i, sl["title"] or "(cover)", flush=True)

run(["save", FILE])
print("written", FILE)
