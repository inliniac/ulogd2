AM_CPPFLAGS = -I$(top_srcdir)/include ${libsqlite3_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

if HAVE_SQLITE3

pkglib_LTLIBRARIES = ulogd_output_SQLITE3.la

ulogd_output_SQLITE3_la_SOURCES = ulogd_output_SQLITE3.c ../../util/db.c
ulogd_output_SQLITE3_la_LIBADD  = ${libsqlite3_LIBS}
ulogd_output_SQLITE3_la_LDFLAGS = -avoid-version -module

endif
