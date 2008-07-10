
AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

man_MANS = ulogd.8

EXTRA_DIST = $(man_MANS) debian ulogd.logrotate ulogd.spec

INCLUDES = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = include doc libipulog src input filter output

noinst_DATA = ulogd.conf

edit = sed \
	-e 's,@libdir\@,$(libdir),g'

ulogd.conf: Makefile $(srcdir)/ulogd.conf.in
	$(edit) $(srcdir)/ulogd.conf.in >ulogd.conf

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

