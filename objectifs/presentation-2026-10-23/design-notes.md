# Design rationale

Rationale behind the composition of the 2026-10-23 progress deck
([slides.pptx](slides.pptx)), which is built on an explicit grid. Content,
wording, palette, font and template chrome are those of the earlier sober
version; only composition changed. The earlier version stays in git history
(commit `e4137c8` and before).

## The grid

Canvas 33.866667 × 19.05 cm. Side margins **2.20 cm** left and right, giving
29.4667 cm of content.

**Horizontal — 12 columns, 0.56 cm gutters.** Column width 1.9422 cm, pitch
2.5022 cm. Two stations are defined:

| Station | Span | Left | Right |
| --- | --- | --- | --- |
| Text zone | cols 1–5 | 2.20 | 14.15 |
| Diagram zone | cols 6–12 | 14.71 | 31.67 |

**Where the stations are actually used.** The two-zone split is a device for the
slides whose argument is one statement plus one structure — slide 2 uses it
directly. Slide 9 uses the same grid but with the column boundary at column 8
(list = cols 1–7, ask panel = cols 8–12), because the ask panel needs the width.
Slides 3, 4, 6, 8 and 10 are full-width compositions: their content is a set of
parallel rows or a card grid that is stronger at full measure than in a narrow
column. Slide 7 is a matrix whose first column is the row labels; it starts at
7.55 cm so the two labelled columns are equal, not on a station boundary. The
declared 12-column grid governs every slide; the two named stations govern the
two-zone ones only.

**Vertical — fixed on all content slides:**

| Band | y (cm) |
| --- | --- |
| Top bar (tabs, logo) | 0.60 – 1.50 |
| Title zone | 1.70 – 3.50 |
| Crimson rule | 3.62 |
| Body zone | 4.45 – 14.55 |
| Hairline opening the caption band | 14.82 |
| Caption (takeaway, crimson 21 pt fixed) | 14.88 – 17.20 |
| Support line (muted 13.5 pt), under the takeaway | follows the takeaway |
| Footer | 17.90 |

The caption is now a real band, not a floating line: the hairline, the fixed
baseline and a **fixed 21 pt size** make every takeaway land in the same place
at the same weight whatever the diagram above it does. The size is set directly
rather than through `fit_size`, because fitting a long caption shrank it below
the 15 pt body it summarises (slide 8 had drifted to 13.5 pt). Long captions
wrap to a second line inside the band; the support line then hangs under the
measured line count. Body content always ends above 14.55, so no slide crowds
the caption. All nine body slides carry a caption.

## Per-slide changes

**1 — Cover.** Title block left, on the same 2.2 cm margin as every body. The
hairline that used to be implicit is now explicit under the subtitle, and the
"work in progress" status sits in a crimson-barred rose panel so it reads as a
declared status rather than a stray italic line.

**2 — The objective.** Was a centred headline over a bus with three branches.
Now a two-zone page: the objective sentence holds the text zone (25 pt, three
lines, hanging at the top of the body zone), and the three commitments are a
stacked list in the diagram zone — each a ruled row with a crimson stem, so the
list reads top to bottom instead of left to right. The bridge rule and its
stems are gone; the sentence and the list are simply adjacent, which is the
actual relation.

**3 — The instrument.** Was three small nodes with arrows on an empty page. Now
three full-width bands, each with a coloured accent bar (grey / blue / crimson).
Head and description share one station across all three rows (head at
`ML + 1.15`, description at `ML + 7.55`), so the rows read as a table. The
station was first set wider; on "Laboratory / networks with known ground truth"
that left the label and its description looking like two disconnected columns.
Short, axis-aligned links in the accent column join the bands.

**4 — What constitutes a finding.** The two counter-panels stay opposite (left
grey, right rose) and grew to 6.05 cm. The methodological second half — healthy
vs vulnerable — moved out of loose centred text and into a blue panel across the
full width, so it reads as part of the rule rather than an afterthought.

**5 — Current status.** Was centred headline, two short bars, centred result.
Now a left-hand statement in the text zone and two full-width bars in the
diagram zone, each labelled at the left and counted at the right ("6 / 6"). The
bars are drawn to the full width of the scale because saturation *is* the
finding; the caption carries "does not discriminate" and the support line
carries the attribution to the instrument.

**6 — The register.** Six cards keep the 3 × 2 grid but are now sized from the
12-column grid (card = 4 columns) and use a header rule to separate the
hypothesis name from its test. H1–H5 carry an ink code and H6 a crimson one, as
in the reference deck — that colour contrast is what marks H6 as a risk rather
than a gain, and it is backed by the rose card. Card heights were raised to
3.95 cm so the second line of text never sits against the border.

**7 — V0.** The four outcomes were two columns of cards with the arms repeated
in each. Now an actual 2 × 2 matrix: row labels `script ✓ / script ✗` on the
left, column labels `model ✗ / model ✓` above, four cells. Because the cell
order changed, the caption and the speaker note name the valid cell **by
identity, never by ordinal**: the caption reads "Only a control that the script
and the model both pass…" and the note says "the one where both arms pass". An
ordinal would have pointed at the wrong quadrant for anyone reading in row-major
order. Cell assignment is
`(script ✓, model ✗)` = a defect in the instrument; `(script ✓, model ✓)` =
valid; `(script ✗, model ✗)` = beyond reach; `(script ✗, model ✓)` = a gain or
a coverage gap. The green cell therefore sits on **script ✓ / model ✓**, which
is what the V0 gate means and what the caption states. The framing sentence
moved to a grey subtitle line under the title, snapped to the body top.

**8 — What we cannot claim.** Three cards became three full-width rows with a
crimson `✕` column, the claim in crimson, and the reason in ink at a fixed
station. Rows are easier to read aloud in sequence than three columns, and the
row form matches slides 2, 3 and 8 to each other.

**9 — Next steps.** Was a list on the left with a boxed ask underneath. Now the
list holds columns 1–7 with numbered items and hairlines, and the ask moves to
a rose panel in columns 8–12, aligned with the list's first item. The two
requested forms of support are parallel ruled items rather than one line with a
`·` separator: the separator did not survive a wrap at this width, and the
parallel form carries the same relation without a typographic dependency.

The caption is the slide's own closing line, "Order follows conditions, not
dates.", which is that slide's approved speaker note in the reference deck. The
AsiaCCS deadline is the **support line**, not the caption: it is administrative,
not the conclusion, and a 21 pt crimson deadline in the caption band would have
made a date the takeaway of the page.

**10 — Reserve.** Seven items became two columns, four and three, with dashes
and hairlines. The divider under the last row of each column is suppressed so it
does not read as an empty cell. The slide now carries a caption, which is the
sentence already in its speaker notes, not a new claim.

## What was rejected

- **Diagonal connectors between nodes** (slide 3 in the original): officecli
  anchors connectors to bounding-box corners, so they cut across panels. Kept
  the explicit stem pattern from the reference script.
- **A full-width headline above a full-width diagram** (slide 4 first attempt):
  the headline competed with the title zone and the page lost its reading order.
- **Rounded panels carrying a flush left accent bar** (slides 2, 3, 6, 7, 8):
  the bar and the corner radius cannot share an edge; the bar appeared to
  float. Every panel with a flush bar is therefore square-cornered — slide 6's
  six cards included, which is why they read as a table like slide 7's cells.
  Rounded corners are kept only on the two counters of slide 4, which carry no
  bar; every panel with a flush bar is square.
- **One pitch for both columns on slide 10**: with four rows on the left and
  three on the right, a single pitch left the right column hanging above a
  dead cell. Each column now gets a pitch of its own (2.45 cm and 3.675 cm)
  over the same vertical extent, so the two columns start and end together.

## Verification

- `officecli validate slides.pptx` — no errors.
- `officecli view slides.pptx issues` — **0 issues** (no text overflow, no
  overlap). Rebuilt after review with `officecli close` first; overflow found
  during the loop (slide 7 subtitle) was fixed.
- Content parity checked against the earlier deck (git `e4137c8`) with
  `officecli view text` on both files: the only differences are re-wrapping, the
  removal of repeated arm labels in slide 7 (now carried once by the matrix
  headers), the dash marker on slide 10, and the split of the slide 9 deadline
  line.
- Visual inspection of all 10 rendered pages
  (`officecli view slides.pptx screenshot --page N`, 1600 × 900).
- Speaker notes are preserved on all 10 slides (10 notes parts in the package)
  and were rewritten for slides 2, 3, 5, 7, 9, 10 to match the new compositions.
  No note introduces wording that is absent from the reference deck.
- Text sizing is recomputed by `fit_size()` from Arial metrics with the same
  1.18 / 1.55 slack factors as the reference script, so the renderer's wider
  fallback face is accounted for.

**Limit.** Rendering is officecli's HTML engine, not PowerPoint. The deck should
still be opened once in PowerPoint before the session.

## Review pass

Eight defects were raised against the first build and all eight are fixed:

1. Slide 7 matrix cells transposed — `(script ✓, model ✓)` is now the green
   "valid" cell and `(script ✗, model ✓)` the "gain or coverage gap" cell.
2. Slide 6 `R if h6 else R` dead conditional — H1–H5 are ink again.
3. Slides 9 and 10 had no caption band — both now do, all nine body slides.
4. Caption size varied (18.5 pt on 4, 13.5 pt on 8) — the caption is set at a
   fixed 21 pt outside `fit_size`, and wraps inside a taller band.
5. `TEXT_X/TEXT_W`/`DIAG_X/DIAG_W` were described as reused deck-wide — the
   section above now states exactly where they apply.
6. Body-zone top drifted — slides 5 and 7 now start at the declared 4.45.
7. Slide 9 lost the `·` separator — the two items are now parallel ruled rows.
8. Slide 2 note invented "not on the critical path" — removed.

## Review pass 2

1. Slide 7 caption said "the fourth outcome". With the corrected cell order the
   fourth cell is `(script ✗, model ✓)`, so the caption named the wrong quadrant
   — the transposition again, one layer up. The caption now identifies the cell
   by its condition, not its position.
2. Slide 7 note said "the bottom right one", which is now `(1,1)`. Rewritten to
   name the cell by its arms.
3. Slide 9's caption was the AsiaCCS deadline. Moved back to the support line;
   the caption is now that slide's own closing line from the reference note.
4. Slide 2 had an orphaned crimson rule under the sentence. Removed.
5. Slide 3's description station was too wide; pulled in to `ML + 7.55` so the
   three rows read as a table.

The dark band at the bottom of the rendered PNGs is the HTML renderer's
viewport, not a shape: nothing is drawn below `FOOT_Y = 17.90`.

## Review pass 3

1. Slide 10 ran its seven items through `fit_size`: 16 / 13.5 / 15.5 pt in one
   list. Fixed with `sized()` at 16 pt for all seven.
2. Slide 9's panel head was smaller than its own content (13.5 pt under 16 pt)
   and step 3 had shrunk to 17.5 pt beside 20 pt neighbours. The head is now
   pinned at 17 pt and the four steps at 20 pt, with the list widened to the
   ask panel's gutter.
3. Slide 10 had a dead cell. Replaced by giving each column its own pitch over
   the same extent (see "What was rejected").
4. This file's preset rule did not describe the file: slide 6's cards were
   round-cornered and carried a flush bar. The cards are now square, and the
   rule names every slide it governs.
5. Slide 5 left a void under a single sentence. The sentence is pinned at a
   true 26 pt in a box sized to its content, with the rule beneath it.

A type-size audit of the built XML (`sz` attribute per run, all ten parts)
followed, because the same `fit_size` drift had reached other groups the review
had not itemised: the chrome tabs (9.5 pt), the cover title (18 pt), slide 2's
sentence and row heads, slide 3's rows, slide 4's counters, slide 5's labels,
slide 6's card titles (13.0 vs 13.5 pt), slide 7's subtitle and axis labels.
Every one of these is now emitted through `sized()` at the size the layout
declares, and every remaining run in the deck matches its declared size. The
rule the audit enforces is the one in the caption band: a stated size is a
design decision; `fit_size` is for prose that has to fill an unbounded box, not
for a list, a table or a label.

## Structure revision (2026-10-22)

The deck was re-sequenced so the argument reads in order:

- **Platform overview added** (slide 3). The platform is presented in general
  terms before the instrument: six phases per run, four execution modes, and a
  dashboard capture (`assets/platform-dashboard.jpg`, 16 × 10 cm, same
  diagram-zone station as slide 2). The capture is from the running instance;
  the Benchmark capture was left out because its F1 figures come from individual
  runs, which the deck itself says are not a measurement.
- **Control before status.** The V0 gate (slide 6) is defined before the
  status slide (slide 7) that reports its outcome. Previously the conclusion
  came first. V0 is defined on first use.
- **Sections re-cut.** `Control` is a section of its own; V0 and the status no
  longer sit under `Hypotheses`. Five tabs at a 5.0 cm pitch.
- **"The register" defined** on slide 8, where it first appears, in the
  caption's support line.
- Slide 6's speaker note says "hypotheses" instead of "register", since the
  register is now defined later in the deck.

Unchanged: content of the other slides, palette, grid, caption band. The bars
on slide 7 were kept; replacing them with a sentence and a table is still an
open option.

