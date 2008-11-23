# the autoconf initilization.
AC_INIT(pppd-sql, 0.2.0, [mbroemme@plusserver.de], [pppd-sql])

# detect the canonical host and target build environment.
AC_CANONICAL_SYSTEM

# initialize autoconf and automake system.
AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])

# notices.
AC_PREREQ(2.53)
AC_REVISION($Revision: 1.6 $)

# checking for required binaries.
AC_PATH_PROG([rmpath], [rm], [no])
if test "$rmpath" = "no"; then
	AC_MSG_ERROR([*** rm binary is required, install coreutils files])
fi
AC_PATH_PROG([sedpath], [sed], [no])
if test "$sedpath" = "no"; then
	AC_MSG_ERROR([*** sed binary is required, install sed files])
fi

# checking if static is enabled, which is impossible to use.
if test "$enable_static" = "yes"; then
	AC_MSG_ERROR([*** static linking is not possible, dlopen() is required by module loading])
fi

# checking for programs.
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_CC

# checking for pppd binary.
AC_PATH_PROG([pppdpath], [pppd], [no])
if test "$pppdpath" = "no"; then
	AC_MSG_ERROR([*** pppd binary is required, install ppp server files])
else

	# checking for pppd version.
	AC_MSG_CHECKING([for pppd version])
	PPPD_VERSION="$($pppdpath --version 2>&1 | $sedpath 's/.* //')"
	case "$PPPD_VERSION" in
		0.*|1.*|2.0.*|2.1.*|2.2.*|2.3.1|2.3.1.*|2.3.2*|2.3.3*|2.3.4*|2.3.5*|2.3.6*|2.3.7*|2.3.8*|2.3.9*)
			AC_MSG_ERROR([*** pppd version below 2.3.10 has no plugin support])
		;;
		*)
			AC_MSG_RESULT([yes (found $PPPD_VERSION)])
		;;
	esac
fi

# checking for ppp include.
AC_CHECK_HEADER([pppd/pppd.h], [], [AC_MSG_ERROR([*** pppd.h is required, install ppp header files])])

# checking for plugin path.
AC_ARG_WITH([plugin_path], AS_HELP_STRING([--with-plugin-path=<path>], [the PPP plugin directory for installation]))
if test "$withval" = "no" -o "$withval" = "yes"; then
	if test "$with_plugin_path" = "yes"; then
		AC_MSG_WARN([*** configure option '--with-plugin-path' but no path was specified, using default])
		libdir="$libdir/pppd/$PPPD_VERSION"
	else
		libdir="$libdir/pppd/$PPPD_VERSION"
	fi
fi
if test "$withval" != "no" -a "$withval" != "yes"; then
	case "$with_plugin_path" in
		/*)
			libdir="$with_plugin_path"
		;;
		*)
			AC_MSG_ERROR([*** configure option '--with-plugin-path=$with_plugin_path' but path must be absolute])
		;;
	esac
fi

# checking for mysql include.
AC_CHECK_HEADER([mysql/mysql.h], [], [AC_MSG_ERROR([*** mysql.h is required, install mysql header files])])
if test "$ac_cv_header_mysql_mysql_h" = "yes"; then
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
if test "$ac_cv_header_libpq_fe_h" = "yes"; then
	PGSQL_CFLAGS="$(pg_config --cflags)"
	PGSQL_LDFLAGS="-L$(pg_config --libdir) -lpq"
	AC_SUBST(PGSQL_CFLAGS)
	AC_SUBST(PGSQL_LDFLAGS)

	# define the postgresql name and version.
	AC_DEFINE_UNQUOTED(PLUGIN_NAME_PGSQL, "pgsql", [Plugin name as Prefix.])
	AC_DEFINE_UNQUOTED(PLUGIN_VERSION_PGSQL, "$(pg_config --version | $sedpath 's/.* //')", [Plugin version for PostgreSQL.])
else
	AC_MSG_ERROR([*** postgresql is required, install postgresql library files])
fi

# creating files.
AC_OUTPUT([
Makefile
doc/Makefile
src/Makefile
])
