MAIN := main
TEX  := $(MAIN).tex
PDF  := $(MAIN).pdf
LATEX := pdflatex -interaction=nonstopmode -halt-on-error
BIBTEX := bibtex

.PHONY: all clean watch count check

all: $(PDF)

$(PDF): $(TEX) references.bib $(wildcard sections/*.tex)
	$(LATEX) $(MAIN) || (cat $(MAIN).log | tail -40; false)
	$(BIBTEX) $(MAIN) || true
	$(LATEX) $(MAIN) > /dev/null
	$(LATEX) $(MAIN) > /dev/null || (cat $(MAIN).log | tail -40; false)

clean:
	rm -f *.aux *.log *.bbl *.blg *.out *.toc *.lof *.lot *.fls *.fdb_latexmk
	rm -f sections/*.aux

watch:
	@command -v latexmk >/dev/null || { echo "latexmk required"; exit 1; }
	latexmk -pdf -pvc -interaction=nonstopmode $(MAIN)

count:
	@command -v texcount >/dev/null || { echo "texcount required"; exit 1; }
	@texcount -inc -total $(TEX)

check:
	@command -v chktex >/dev/null && chktex $(TEX) || echo "chktex not installed; skipping"
