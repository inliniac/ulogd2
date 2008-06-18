
INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-fPIC -Wall
LIBS=

pkglib_LTLIBRARIES = ulogd_inppkt_NFLOG.la ulogd_inppkt_ULOG.la

ulogd_inppkt_NFLOG_la_SOURCES = ulogd_inppkt_NFLOG.c
ulogd_inppkt_NFLOG_la_LDFLAGS = -module $(LIBNETFILTER_LOG_LIBS)
ulogd_inppkt_NFLOG_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_LOG_CFLAGS)

ulogd_inppkt_ULOG_la_SOURCES = ulogd_inppkt_ULOG.c
ulogd_inppkt_ULOG_la_LDFLAGS = -module
ulogd_inppkt_ULOG_la_LIBADD = ../../libipulog/libipulog.la
