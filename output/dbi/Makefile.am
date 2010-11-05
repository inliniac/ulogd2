
AM_CPPFLAGS = -I$(top_srcdir)/include $(DBI_INC)
LIBS=$(DBI_LIB)

if HAVE_DBI

pkglib_LTLIBRARIES = ulogd_output_DBI.la

ulogd_output_DBI_la_SOURCES = ulogd_output_DBI.c ../../util/db.c
ulogd_output_DBI_la_LDFLAGS = -avoid-version -module

endif
