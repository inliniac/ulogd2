
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglibexec_LTLIBRARIES = ulogd_inpflow_NFCT.la # ulogd_inpflow_IPFIX.la

ulogd_inpflow_NFCT_la_SOURCES = ulogd_inpflow_NFCT.c
ulogd_inpflow_NFCT_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_CONNTRACK_LIBS)
ulogd_inpflow_NFCT_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_CONNTRACK_CFLAGS)

#ulogd_inpflow_IPFIX_la_SOURCES = ulogd_inpflow_IPFIX.c
#ulogd_inpflow_IPFIX_la_LDFLAGS = -avoid-version -module
