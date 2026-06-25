# Minimal makefile for Sphinx documentation.
#
# Build with the project virtualenv so `pygamlastan` is importable, e.g.:
#   make -C docs html SPHINXBUILD="../.venv/bin/python -m sphinx"

SPHINXBUILD   ?= python -m sphinx
SOURCEDIR     = .
BUILDDIR      = _build

.PHONY: help html clean

help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

clean:
	rm -rf "$(BUILDDIR)"

# Catch-all: route html, linkcheck, etc. to sphinx-build.
%:
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)
