#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([anti-tamper], [1.0.0], [freewaf@163.com])
AM_INIT_AUTOMAKE(anti-tamper, 1.0.0)
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h paths.h stddef.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/socket.h sys/time.h sys/vfs.h syslog.h unistd.h utime.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([ftruncate gettimeofday memset mkdir rmdir select socket strchr strerror strncasecmp strrchr strstr utime])
AC_PREFIX_DEFAULT([/usr/local/waf/anti-tamper])

# --with-apr 
AC_ARG_WITH(apr, AS_HELP_STRING([--with-apr=PATH],[prefix for installed APR or the full path to apr-config]), with_args=yes, with_args=no)
	if test "$with_args"="yes"; then 
		CFLAGS="$CFLAGS -D_LARGEFILE64_SOURCE -I$withval/include/apr-1" 
	        LDFLAGS="$LDFLAGS -L$withval/lib  -Wl,-rpath,$withval/lib"
		LIBS="$LIBS -lapr-1"
	else
		CFLAGS="$CFLAGS"
		LDFLAGS="$LDFLAGS"
		LIBS="$LIBS"
	fi 

# --with-apu 
AC_ARG_WITH(apr-util, AS_HELP_STRING([--with-apr-util=PATH],[prefix for installed APU or the full path to apu-config]), with_args=yes, with_args=no)
	if test "$with_args"="yes"; then 
		CFLAGS="$CFLAGS -I$withval/include/apr-1" 
        	LDFLAGS="$LDFLAGS -L$withval/lib -Wl,-rpath,$withval/lib -Wl,-rpath,$withvalue/lib/apr-util-1"
		LIBS="$LIBS -laprutil-1"
	else
		CFLAGS="$CFLAGS"
		LDFLAGS="$LDFLAGS"
		LIBS="$LIBS"
	fi 


# --with-ssh2 
AC_ARG_WITH(ssh2, AS_HELP_STRING([--with-ssh2=PATH],[prefix for installed SSH2]), with_args=yes, with_args=no)
	if test "$with_args"="yes"; then 
		CFLAGS="$CFLAGS -I$withval/include" 
        	LDFLAGS="$LDFLAGS -L$withval/lib -Wl,-rpath,$withval/lib"
		LIBS="$LIBS -lssh2"
	else
		CFLAGS="$CFLAGS"
		LDFLAGS="$LDFLAGS"
		LIBS="$LIBS"
	fi 

# --with-cparser 
AC_ARG_WITH(cparser, AS_HELP_STRING([--with-cparser=PATH],[prefix for installed CPARSER]), with_args=yes, with_args=no)
	if test "$with_args"="yes"; then 
		CFLAGS="$CFLAGS -I$withval/include" 
        	LDFLAGS="$LDFLAGS -L$withval/lib -Wl,-rpath,$withval/lib"
		LIBS="$LIBS -lcparser"
	else
		CFLAGS="$CFLAGS"
		LDFLAGS="$LDFLAGS"
		LIBS="$LIBS"
	fi 

LIBS="$LIBS -lcrypto"
$SHELL $srcdir/generate.sh "#define ROOT_PATH \"$prefix\"\n"

AC_OUTPUT([Makefile])

