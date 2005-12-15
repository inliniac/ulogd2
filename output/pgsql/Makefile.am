
INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(PGSQLINCLUDES)
LIBS=$(PGSQL_LIB)

pkglib_LTLIBRARIES = ulogd_output_PGSQL.la

ulogd_output_PGSQL_la_SOURCES = ulogd_output_PGSQL.c ../../util/db.c
ulogd_output_PGSQL_la_LDFLAGS = -module

