
INCLUDES = $(all_includes) -I$(top_srcdir)/include
LIBS=-lmysqlclient_r

pkglib_LTLIBRARIES = ulogd_output_MYSQL.la

ulogd_output_MYSQL_la_SOURCES = ulogd_output_MYSQL.c ../../util/db.c
ulogd_output_MYSQL_la_LDFLAGS = -module

