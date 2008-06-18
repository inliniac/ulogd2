
INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-fPIC -Wall

pkglib_LTLIBRARIES = ulogd_inpflow_NFCT.la # ulogd_inpflow_IPFIX.la

ulogd_inpflow_NFCT_la_SOURCES = ulogd_inpflow_NFCT.c
ulogd_inpflow_NFCT_la_LDFLAGS = -module $(LIBNETFILTER_CONNTRACK_LIBS)
ulogd_inpflow_NFCT_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_CONNTRACK_CFLAGS)

#ulogd_inpflow_IPFIX_la_SOURCES = ulogd_inpflow_IPFIX.c
#ulogd_inpflow_IPFIX_la_LDFLAGS = -module
