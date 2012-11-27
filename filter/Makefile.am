SUBDIRS = raw2packet packet2flow

AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBNFNETLINK_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = ulogd_filter_IFINDEX.la ulogd_filter_PWSNIFF.la \
			 ulogd_filter_PRINTPKT.la ulogd_filter_PRINTFLOW.la \
			 ulogd_filter_IP2STR.la ulogd_filter_IP2BIN.la \
			 ulogd_filter_HWHDR.la ulogd_filter_MARK.la \
			 ulogd_filter_IP2HBIN.la

ulogd_filter_IFINDEX_la_SOURCES = ulogd_filter_IFINDEX.c
ulogd_filter_IFINDEX_la_LDFLAGS = -avoid-version -module
ulogd_filter_IFINDEX_la_LIBADD  = ${LIBNFNETLINK_LIBS}

ulogd_filter_PWSNIFF_la_SOURCES = ulogd_filter_PWSNIFF.c
ulogd_filter_PWSNIFF_la_LDFLAGS = -avoid-version -module

ulogd_filter_IP2STR_la_SOURCES = ulogd_filter_IP2STR.c
ulogd_filter_IP2STR_la_LDFLAGS = -avoid-version -module

ulogd_filter_IP2BIN_la_SOURCES = ulogd_filter_IP2BIN.c
ulogd_filter_IP2BIN_la_LDFLAGS = -avoid-version -module

ulogd_filter_IP2HBIN_la_SOURCES = ulogd_filter_IP2HBIN.c
ulogd_filter_IP2HBIN_la_LDFLAGS = -avoid-version -module

ulogd_filter_HWHDR_la_SOURCES = ulogd_filter_HWHDR.c
ulogd_filter_HWHDR_la_LDFLAGS = -avoid-version -module

ulogd_filter_MARK_la_SOURCES = ulogd_filter_MARK.c
ulogd_filter_MARK_la_LDFLAGS = -avoid-version -module

ulogd_filter_PRINTPKT_la_SOURCES = ulogd_filter_PRINTPKT.c ../util/printpkt.c
ulogd_filter_PRINTPKT_la_LDFLAGS = -avoid-version -module

ulogd_filter_PRINTFLOW_la_SOURCES = ulogd_filter_PRINTFLOW.c ../util/printflow.c
ulogd_filter_PRINTFLOW_la_LDFLAGS = -avoid-version -module
