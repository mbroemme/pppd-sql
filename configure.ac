# the autoconf initilization.
AC_INIT(pppd-sql, 0.1.0, [mbroemme@plusserver.de], [pppd-sql])

# detect the canonical host and target build environment.
AC_CANONICAL_SYSTEM

# initialize autoconf and automake system.
AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])

# notices.
AC_PREREQ(2.53)
AC_REVISION($Revision: 1.6 $)

# checking for programs.
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_CC

# checking for ppp include.
AC_CHECK_HEADER([pppd/pppd.h], [], [AC_MSG_ERROR([*** pppd.h is required, install ppp header files])])

# checking for mysql include.
AC_CHECK_HEADER([mysql/mysql.h], [], [AC_MSG_ERROR([*** mysql.h is required, install mysql header files])])
if test "$ac_cv_header_mysql_mysql_h" = yes; then
	MYSQL_CFLAGS="$(mysql_config --cflags)"
	MYSQL_LDFLAGS="$(mysql_config --libs)"
	AC_SUBST(MYSQL_CFLAGS)
	AC_SUBST(MYSQL_LDFLAGS)

	# define the mysql name and version.
	AC_DEFINE_UNQUOTED(PLUGIN_NAME_MYSQL, "mysql", [Plugin name as Prefix.])
	AC_DEFINE_UNQUOTED(PLUGIN_VERSION_MYSQL, "$(mysql_config --version)", [Plugin version for MySQL.])
else
	AC_MSG_ERROR([*** mysql is required, install mysql library files])
fi

# checking for postgresql include.
AC_CHECK_HEADER([libpq-fe.h], [], [AC_MSG_ERROR([*** libpq-fe.h is required, install postgresql header files])])
if test "$ac_cv_header_libpq_fe_h" = yes; then
	PGSQL_CFLAGS="$(pg_config --cflags)"
	PGSQL_LDFLAGS="-L$(pg_config --libdir) -lpq"
	AC_SUBST(PGSQL_CFLAGS)
	AC_SUBST(PGSQL_LDFLAGS)

	# define the postgresql name and version.
	AC_DEFINE_UNQUOTED(PLUGIN_NAME_PGSQL, "pgsql", [Plugin name as Prefix.])
	AC_DEFINE_UNQUOTED(PLUGIN_VERSION_PGSQL, "$(pg_config --version | sed 's/.* //')", [Plugin version for PostgreSQL.])
else
	AC_MSG_ERROR([*** postgresql is required, install postgresql library files])
fi

# creating files.
AC_OUTPUT([
Makefile
doc/Makefile
src/Makefile
])
