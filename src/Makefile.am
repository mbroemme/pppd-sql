# minimum required automake 1.6
AUTOMAKE_OPTIONS	= 1.6

# library information and headers which should not be installed.
lib_LTLIBRARIES		= mysql.la pgsql.la
noinst_HEADERS		= auth-mysql.h auth-pgsql.h plugin.h plugin-mysql.h plugin-pgsql.h str.h

# sources to compile.
mysql_la_SOURCES	= auth-mysql.c \
			  plugin.c \
			  plugin-mysql.c \
			  str.c
# compile flags.
mysql_la_CFLAGS		= @MYSQL_CFLAGS@

# linker options.
mysql_la_LDFLAGS	= @MYSQL_LDFLAGS@ \
			  -module \
			  -avoid-version

# sources to compile.
pgsql_la_SOURCES	= auth-pgsql.c \
			  plugin.c \
			  plugin-pgsql.c \
			  str.c

# compile flags.
pgsql_la_CFLAGS		= @PGSQL_CFLAGS@

# linker options.
pgsql_la_LDFLAGS	= @PGSQL_LDFLAGS@ \
			  -module \
			  -avoid-version
