AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = ulogd_inpflow_NFACCT.la

ulogd_inpflow_NFACCT_la_SOURCES = ulogd_inpflow_NFACCT.c
ulogd_inpflow_NFACCT_la_LDFLAGS = -avoid-version -module $(LIBMNL_LIBS) $(LIBNETFILTER_ACCT_LIBS)
ulogd_inpflow_NFACCT_la_CFLAGS = $(AM_CFLAGS) $(LIBMNL_LIBS) $(LIBNETFILTER_ACCT_CFLAGS)
