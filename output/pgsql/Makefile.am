
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(PQINCPATH)
AM_CFLAGS = ${regular_CFLAGS}

if HAVE_PGSQL

pkglib_LTLIBRARIES = ulogd_output_PGSQL.la

ulogd_output_PGSQL_la_SOURCES = ulogd_output_PGSQL.c ../../util/db.c
ulogd_output_PGSQL_la_LIBADD  = ${PQLIBS}
ulogd_output_PGSQL_la_LDFLAGS = -avoid-version -module

endif
