NAME=talk

$(NAME).pdf: $(NAME).tex beamerthemeegi.sty
	pdflatex $(NAME).tex

all: $(NAME).tex $(NAME).bib
	pdflatex $(NAME).tex
	bibtex $(NAME)
	pdflatex $(NAME).tex
	pdflatex $(NAME).tex

clean : 
	rm -f *.aux *.bbl *.blg *.lof *.log *.lot *.out *.pdf *.toc *~ *.nav *.snm *.vrb

