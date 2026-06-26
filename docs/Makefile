# Minimal makefile for Sphinx documentation.
#
# Builds with the project virtualenv (../.venv) when present so `pygamlastan` is
# importable; override with e.g. `make html SPHINXBUILD="python -m sphinx"`.

ifneq (,$(wildcard ../.venv/bin/python))
SPHINXBUILD   ?= ../.venv/bin/python -m sphinx
else
SPHINXBUILD   ?= python -m sphinx
endif
SOURCEDIR     = .
BUILDDIR      = _build

# Only targets that have their own recipe are phony. html/linkcheck/etc. must
# NOT be listed here, or their empty explicit entry shadows the catch-all below
# and make reports "Nothing to be done".
.PHONY: help clean Makefile

help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

clean:
	rm -rf "$(BUILDDIR)"

# Catch-all: route html, linkcheck, etc. to sphinx-build (-M <target>).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)
