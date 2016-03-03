PACKAGE := $(shell grep '^Package:' DESCRIPTION | sed -E 's/^Package:[[:space:]]+//')
RSCRIPT = Rscript --no-init-file

all: install

test:
	${RSCRIPT} -e 'library(methods); devtools::test()'

roxygen:
	@mkdir -p man
	${RSCRIPT} -e "library(methods); devtools::document()"

install:
	R CMD INSTALL .

build:
	R CMD build .

check: build
	_R_CHECK_CRAN_INCOMING_=FALSE R CMD check --as-cran --no-manual `ls -1tr ${PACKAGE}*gz | tail -n1`
	@rm -f `ls -1tr ${PACKAGE}*gz | tail -n1`
	@rm -rf ${PACKAGE}.Rcheck

staticdocs:
	@mkdir -p inst/staticdocs
	Rscript -e "library(methods); staticdocs::build_site()"
	rm -f vignettes/*.html
	@rmdir inst/staticdocs
website: staticdocs
	./update_web.sh

vignettes/data.Rmd: vignettes/src/data.R
	${RSCRIPT} -e 'library(sowsear); sowsear("$<", output="$@")'
vignettes/encryptr.Rmd: vignettes/src/encryptr.R
	${RSCRIPT} -e 'library(sowsear); sowsear("$<", output="$@")'

vignettes: vignettes/data.Rmd vignettes/encryptr.Rmd
	${RSCRIPT} -e 'library(methods); devtools::build_vignettes()'

README.md: README.Rmd
	Rscript -e 'library(methods); devtools::load_all(); knitr::knit("README.Rmd")'
	sed -i.bak 's/[[:space:]]*$$//' $@
	rm -f $@.bak

.PHONY: all test document install vignettes check build staticdocs website
