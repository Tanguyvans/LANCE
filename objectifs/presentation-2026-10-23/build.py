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
box("An autonomous and verifiable auditor\nfor IoT/IIoT networks", 3.4, 6.4, 26, 2.4,
    25, M)
box("Progress report — NATO SPS G6259", 3.4, 10.4, 26, 1.0, 18, R, bold=True)
box("23 October 2026  ·  Université de Mons, ILIA", 3.4, 11.4, 26, 0.9, 15, M)
box("Status: work in progress.", 3.4, 13.6, 26, 0.9, 14, M, italic=True)
picture(LOGO, 26.9, 1.4, 5.2, 5.2 * 463 / 1351, "SMart ILIA — UMONS")

# --------------------------------------------------------- 2. The objective
page("The objective",
     "One sentence, then three commitments. Do not read the boxes aloud; the "
     "diagram carries it.", seconds=60, sect=0)

box("An auditor that explores, identifies,\nverifies and reports.",
    4.0, 4.9, 26.0, 2.8, 30, INK, bold=True, align="center")

box("", 16.85, 8.1, 0.06, 0.7, fill=R)
box("", 2.2, 8.9, 29.4, 0.06, fill=R)

for i, (head, sub) in enumerate([
    ("Under which conditions", "rather than which model prevails"),
    ("Identical tools and budget", "for both approaches"),
    ("Evidence, not assertion", "recomputed from the log"),
]):
    x = 2.2 + i * 10.1
    node(f"c{i}", head, x, 9.5, 9.2, 1.8, GRAY, INK, LINE, 19)
    box(sub, x, 11.5, 9.2, 0.9, 14, M, align="center")
    box("", x + 4.55, 8.96, 0.09, 0.5, fill=R)

box("Model training is not a current priority.", 2.2, 14.3, 29.4, 0.9, 16, R,
    bold=True, align="center")

# ------------------------------------------------------- 3. The instrument
page("The instrument",
     "Three pieces, three roles. The model is one piece among them.",
     seconds=50, sect=1)

node("lab", "Laboratory", 2.4, 6.0, 8.4, 1.9, GRAY, INK, LINE, 23)
box("networks with known ground truth", 2.4, 8.1, 8.4, 0.9, 15, M, align="center")

node("plat", "Platform", 12.7, 6.0, 8.4, 1.9, BLUE, B, B, 23)
box("conducts the audit", 12.7, 8.1, 8.4, 0.9, 15, M, align="center")

node("bench", "Benchmark", 23.0, 6.0, 8.4, 1.9, ROSE, R, R, 23)
box("assesses the result", 23.0, 8.1, 8.4, 0.9, 15, M, align="center")

arrow("lab", "plat", M, 2.4)
arrow("plat", "bench", M, 2.4)

box("The model is one component among them.", 2.4, 11.6, 29.0, 1.2, 24, R,
    bold=True, align="center")
box("A run constitutes a measurement only against known ground truth.",
    2.4, 13.4, 29.0, 0.9, 14, M, align="center")

# ------------------------------------------------- 4. What counts as found
page("What constitutes a finding",
     "Two halves. Left: we recompute from the log, never from the conclusion. "
     "Right: the same trial runs on both configurations, so a false positive "
     "is visible.", seconds=80, sect=1)

box("", 2.2, 5.4, 14.2, 4.8, fill=GRAY, preset="roundRect", line=f"{LINE}:1pt")
box("“I have read another organisation's data.”", 2.7, 5.8, 13.2, 1.6, 17, M,
    align="center", italic=True)
box("✕   Not admitted", 2.7, 8.3, 13.2, 1.1, 24, R, bold=True, align="center")

box("", 17.4, 5.4, 14.2, 4.8, fill=ROSE, preset="roundRect", line=f"{R}:1pt")
box("The request and its response\ncontain the data.", 17.9, 5.8, 13.2, 1.6, 17,
    INK, align="center")
box("✓   Admitted", 17.9, 8.3, 13.2, 1.1, 24, GREEN, bold=True, align="center")

box("The finding is recomputed from the log;\nthe conclusion is never taken on "
    "trust.", 2.2, 11.2, 29.4, 1.9, 21, R, bold=True, align="center")

box("The same trial is conducted on a healthy and on a vulnerable network.\n"
    "A finding reported on the healthy one is recorded as an error.",
    2.2, 13.5, 29.4, 1.6, 14, M, align="center")

# ------------------------------------------------------- 5. Where we are
page("Current status",
     "Both approaches succeed everywhere. That is a property of the instrument, "
     "not a verdict on the model.", seconds=50, sect=2)

box("Both approaches succeed on every configuration.", 2.2, 5.2, 29.4, 1.4, 30,
    INK, bold=True, align="center")

for i, (label, color) in enumerate([("Rule-based", M), ("Model-based", R)]):
    y = 8.0 + i * 2.3
    box(label, 5.2, y, 4.6, 1.2, 18, INK, bold=True)
    box("", 10.4, y + 0.15, 11.8, 0.9, fill=color)  # the scale saturates
    box("6 / 6", 22.8, y, 3.4, 1.2, 21, color, bold=True, align="center")

box("The instrument does not discriminate between them.", 2.2, 13.0, 29.4, 1.2,
    24, R, bold=True, align="center")
box("This is a limitation of the instrument, not of the model.",
    2.2, 14.4, 29.4, 0.9, 14, M, align="center")

# ----------------------------------------------------- 6. The register
page("The objective restated as hypotheses",
     "The objective does not change, its form does. Six network properties, "
     "six tests. H6 is a risk, not a gain.", seconds=75, sect=2)

cards = [
    ("H1", "Connected devices", "a link absent from public inputs"),
    ("H2", "Heterogeneous formats", "a representation no parser covers"),
    ("H3", "Novel contracts", "rights stated in unseen documentation"),
    ("H4", "Vendor semantics", "a field whose meaning is only documented"),
    ("H5", "Ambiguous refusals", "resuming the audit after a refusal"),
    ("H6", "Hostile content", "an instruction obeyed from observed content"),
]
for i, (code, prop, test) in enumerate(cards):
    col, row = i % 3, i // 3
    x = 2.2 + col * 9.9
    y = 5.4 + row * 4.1
    fill, accent = (ROSE, R) if code == "H6" else (GRAY, INK)
    box("", x, y, 9.3, 3.5, fill=fill, preset="roundRect", line=f"{LINE}:1pt")
    box(code, x + 0.6, y + 0.4, 1.6, 0.9, 24, accent, bold=True)
    box(prop, x + 2.5, y + 0.4, 6.2, 0.9, 16, accent, bold=True)
    box(test, x + 0.6, y + 1.8, 8.1, 1.3, 14, M)

box("H1–H5 quantify a possible gain.   H6 quantifies a risk.",
    2.2, 14.0, 29.4, 0.9, 19, R, bold=True, align="center")

# ------------------------------------------------------------- 7. V0
page("A control task before testing the model",
     "The gate is the condition of interpretation for everything else. It "
     "applies to both arms.", seconds=70, sect=2)

box("A control task, simple enough to be solved without inference.\n"
    "Both approaches are required to pass.", 2.4, 4.9, 29.2, 1.9, 24, INK,
    bold=True, align="center")

rows = [
    ("script ✓  model ✗", "a defect in the instrument", R, ROSE),
    ("script ✗  model ✓", "a gain, or a coverage gap", INK, GRAY),
    ("script ✗  model ✗", "beyond the reach of this instrument", M, GRAY),
    ("script ✓  model ✓", "valid — the hypotheses may be read", GREEN, BLUE),
]
for i, (arm, verdict, color, fill) in enumerate(rows):
    x = 2.2 + (i % 2) * 15.0
    y = 7.6 + (i // 2) * 2.6
    box("", x, y, 14.4, 2.2, fill=fill, preset="roundRect", line=f"{LINE}:1pt")
    box(arm, x + 0.7, y + 0.5, 13.0, 0.7, 16, color, bold=True)
    box(verdict, x + 0.7, y + 1.25, 13.0, 0.6, 13, color)

box("Only the fourth outcome permits the hypotheses to be read.",
    2.2, 13.75, 29.4, 0.9, 19, R, bold=True, align="center")
box("Implemented and tested offline. The laboratory run remains outstanding.",
    2.2, 14.9, 29.4, 0.8, 13, M, align="center")

# ------------------------------------------------ 8. What we cannot claim
page("What we cannot claim",
     "Be explicit. This is the slide that buys credibility. Three limits.",
     seconds=60, sect=3)

limits = [
    ("No general advantage", "No hypothesis has yet been executed."),
    ("No confidence interval", "Three repetitions yield a dispersion, "
     "not a sample."),
    ("No admitted evidence", "The metric definition is not frozen."),
]
for i, (head, body) in enumerate(limits):
    x = 2.2 + i * 9.9
    box("", x, 5.4, 9.4, 5.0, fill=GRAY, preset="roundRect", line=f"{LINE}:1pt")
    box("✕", x + 0.7, 5.9, 1.2, 0.9, 22, R, bold=True)
    box(head, x + 0.7, 7.1, 8.0, 1.4, 17, R, bold=True)
    box(body, x + 0.7, 8.6, 8.0, 1.5, 14, INK)

box("A successful run is not a measurement: one early run reported success "
    "while every model arm had failed.", 2.2, 11.4, 29.4, 1.0, 17, R, bold=True,
    align="center")

# --------------------------------------------------------- 9. Next steps
page("Next steps",
     "Order follows conditions, not dates. End by naming what would help.",
     seconds=70, sect=3)

steps = [
    ("1", "Execute V0 on a held-out instance"),
    ("2", "Develop a parameterisable test harness"),
    ("3", "Build the scenario families for H2, H3 and H4"),
    ("4", "Deploy a reproducible platform"),
]
for i, (num, head) in enumerate(steps):
    y = 5.2 + i * 1.85
    box(num, 2.4, y, 1.2, 1.2, 22, R, bold=True)
    box(head, 4.2, y, 21.0, 1.2, 21, INK)
    if i < len(steps) - 1:
        box("", 4.2, y + 1.45, 21.0, 0.04, fill=LINE)

box("", 2.4, 13.1, 29.2, 1.9, fill=ROSE, preset="roundRect")
box("Forms of support requested", 3.2, 13.35, 27.6, 0.7, 15, R, bold=True)
box("access to real vendor artifacts   ·   an adversarial review of the "
    "register", 3.2, 14.0, 27.6, 0.8, 15, INK)

box("AsiaCCS 2027 — submission deadline 11 December 2026 (AoE).", 2.4, 15.5,
    29.2, 0.7, 12.5, M)

# ----------------------------------------------------------- Reserve slide
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
    y = 4.9 + i * 1.5
    box("—", 2.4, y, 1.0, 0.9, 16, R, bold=True)
    box(g, 3.6, y, 28.0, 0.9, 16, INK)

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
