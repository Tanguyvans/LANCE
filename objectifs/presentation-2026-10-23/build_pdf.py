"""Render slides.pptx to slides.pdf, page by page.

There is no PDF exporter for .pptx on this machine (no PowerPoint, no
LibreOffice, no officecli exporter plugin), so each slide is rendered to PNG by
officecli's HTML engine and the images are assembled into a PDF.

The renderer intermittently paints a dark band across the bottom of a page,
which hides the footer. It is an artefact, not a document defect: the same page
renders clean on retry, so each page is re-rendered until its bottom row is
white.

Run:  python3 build_pdf.py
"""

import pathlib
import subprocess
import tempfile

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent
DECK = ROOT / "slides.pptx"
OUT = ROOT / "slides.pdf"
WIDTH, HEIGHT = 2400, 1350
SLIDES = 11
MAX_TRIES = 8


def render(page, dest):
    """Render one slide, retrying while the artefact band is present."""
    for _ in range(MAX_TRIES):
        subprocess.run(
            ["officecli", "view", str(DECK), "screenshot",
             "--page", str(page), "-o", str(dest),
             "--screenshot-width", str(WIDTH),
             "--screenshot-height", str(HEIGHT)],
            cwd=ROOT, check=True, capture_output=True,
        )
        im = Image.open(dest).convert("RGB")
        w, h = im.size
        if im.getpixel((w // 2, h - 3)) == (255, 255, 255):
            return im
    raise RuntimeError(f"page {page}: artefact band did not clear after "
                       f"{MAX_TRIES} renders")


with tempfile.TemporaryDirectory() as tmp:
    pages = [render(i, pathlib.Path(tmp) / f"d{i}.png")
             for i in range(1, SLIDES + 1)]
    print(f"{len(pages)} pages rendered", flush=True)

first = pages[0]
w, h = first.size
first.save(OUT, "PDF", resolution=300.0, save_all=True,
           append_images=pages[1:])
print(f"written {OUT} — {len(pages)} pages, {w}x{h}px each")
