# Top-level Makefile - CS375 Lab A11
#   make             build src/fs_test
#   make test        run every test
#   make report      compile report/report.tex -> report/report.pdf
#   make submission  build everything and fill the submission/ folder + zip
#   make clean       remove build outputs

SHOTS = $(wildcard report/screenshots/*.png report/screenshots/*.jpg report/screenshots/*.jpeg)

all:
	$(MAKE) -C src

test: all
	cd src && ./fs_test

report:
	cd report && pdflatex -interaction=nonstopmode -halt-on-error report.tex >/dev/null \
	          && pdflatex -interaction=nonstopmode -halt-on-error report.tex >/dev/null
	@echo "Report built: report/report.pdf"

submission: rescue-shots all report
	rm -rf submission/source submission/screenshots submission/*.pdf submission/*.zip
	mkdir -p submission/source submission/screenshots
	cp src/simplefs.c src/simplefs.h src/fs_test.c src/Makefile submission/source/
	cp report/report.pdf submission/CS375_A11_Report.pdf
	@if [ -n "$(SHOTS)" ]; then cp $(SHOTS) submission/screenshots/; fi
	cd submission && zip -qr CS375_A11_Submission.zip source screenshots CS375_A11_Report.pdf
	@echo ""
	@echo "Submission folder ready:"
	@find submission -type f ! -name README.md | sort | sed 's/^/   /'
	@n=$$(ls submission/screenshots | wc -l); \
	  if [ $$n -lt 11 ]; then echo ""; echo "   WARNING: only $$n of 11 screenshots found in report/screenshots/"; fi

# Safety net: images accidentally saved in submission/screenshots/ are copied
# (without overwriting) to report/screenshots/ before that folder is rebuilt.
rescue-shots:
	@mkdir -p report/screenshots
	@for f in submission/screenshots/*.png submission/screenshots/*.jpg submission/screenshots/*.jpeg; do \
	  [ -f "$$f" ] && cp -n "$$f" report/screenshots/ && echo "kept $$f -> report/screenshots/"; \
	done; true

clean:
	$(MAKE) -C src clean
	cd report && rm -f *.aux *.log *.out *.toc

.PHONY: all test report submission rescue-shots clean
