AM_CPPFLAGS = -I$(top_srcdir)/include $(LIBNETFILTER_ACCT_CFLAGS) $(LIBMNL_CFLAGS)
AM_CFLAGS = ${regular_CFLAGS}
if BUILD_NFACCT
pkglib_LTLIBRARIES = ulogd_inpflow_NFACCT.la
ulogd_inpflow_NFACCT_la_SOURCES = ulogd_inpflow_NFACCT.c
ulogd_inpflow_NFACCT_la_LDFLAGS = -avoid-version -module
ulogd_inpflow_NFACCT_la_LIBADD  = $(LIBMNL_LIBS) $(LIBNETFILTER_ACCT_LIBS)
endif
