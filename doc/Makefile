all:
	sgml2txt ulogd.sgml
	sgml2latex --papersize=a4 --output=dvi ulogd.sgml
	dvips -t a4 -o ulogd.ps ulogd.dvi
	sgml2html -s 0 ulogd.sgml
clean:
	rm -f ulogd.dvi ulogd.txt ulogd.html ulogd.ps
