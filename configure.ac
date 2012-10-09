dnl Process this file with autoconf to produce a configure script.
AC_INIT([ulogd], [2.0.1])
AC_PREREQ([2.50])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign tar-pax no-dist-gzip dist-bzip2 1.10b])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

dnl Checks for libraries.
AC_SEARCH_LIBS([dlopen], [dl], [libdl_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libdl_LIBS])
AC_SEARCH_LIBS([pcap_close], [pcap], [libpcap_LIBS="-lpcap"; LIBS=""])
AC_SUBST([libpcap_LIBS])
AM_CONDITIONAL([HAVE_PCAP], [test -n "$libpcap_LIBS"])

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(socket strerror)

regular_CFLAGS="-Wall -Wextra -Wno-unused-parameter"
AC_SUBST([regular_CFLAGS])

dnl Check for the right nfnetlink version
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 1.0.1])
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
PKG_CHECK_MODULES([LIBNETFILTER_ACCT], [libnetfilter_acct >= 1.0.1])
PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.2])
PKG_CHECK_MODULES([LIBNETFILTER_LOG], [libnetfilter_log >= 1.0.0])

CT_CHECK_POSTGRES_DB()
AM_CONDITIONAL(HAVE_PGSQL, test "x$PQLIBPATH" != "x")

CT_CHECK_MYSQL_DB()
AM_CONDITIONAL(HAVE_MYSQL, test "x$MYSQL_LIB" != "x")

PKG_CHECK_MODULES([libsqlite3], [sqlite3], [], [:])
AM_CONDITIONAL([HAVE_SQLITE3], [test -n "$libsqlite3_LIBS"])

CT_CHECK_DBI()
AM_CONDITIONAL(HAVE_DBI, test "x$DBI_LIB" != "x")



dnl AC_SUBST(DATABASE_DIR)
dnl AC_SUBST(DATABASE_LIB)
dnl AC_SUBST(DATABASE_LIB_DIR)
dnl AC_SUBST(DB_DEF)
dnl AC_SUBST(EXTRA_MYSQL_DEF)
dnl AC_SUBST(EXTRA_PGSQL_DEF)

dnl AC_SUBST(DATABASE_DRIVERS)

dnl AM_CONDITIONAL(HAVE_MYSQL, test x$mysqldir != x)
dnl AM_CONDITIONAL(HAVE_PGSQL, test x$pgsqldir != x)

AC_CONFIG_FILES(include/Makefile include/ulogd/Makefile include/libipulog/Makefile \
	  include/linux/Makefile include/linux/netfilter/Makefile \
	  libipulog/Makefile \
	  input/Makefile input/packet/Makefile input/flow/Makefile \
	  input/sum/Makefile \
	  filter/Makefile filter/raw2packet/Makefile filter/packet2flow/Makefile \
	  output/Makefile output/pcap/Makefile output/mysql/Makefile output/pgsql/Makefile output/sqlite3/Makefile \
	  output/dbi/Makefile \
	  src/Makefile Makefile Rules.make)
AC_OUTPUT
