
EXTRA_DIST = ulogd.txt ulogd.html ulogd.ps \
	     sqlite3.table pgsql-ulogd2.sql mysql-ulogd2.sql

dist-hook:
	sgml2txt ulogd.sgml
	sgml2latex --papersize=a4 --output=dvi ulogd.sgml
	dvips -t a4 -o ulogd.ps ulogd.dvi
	sgml2html -s 0 ulogd.sgml

