#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([zanssh], [0.1], [zanfire@gmail.com])
AM_INIT_AUTOMAKE(silent-rules)
LT_INIT
AC_CONFIG_SRCDIR([src/base/zString.cpp])
AC_CONFIG_HEADERS([src/base/config.h:config.h.in])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LIBTOOL

AM_PROG_CC_C_O
# 
AM_SILENT_RULES


###############################################################################
# configure compilation
###############################################################################

CXXFLAGS="-Wall -Werror -Wno-uninitialized"


AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug data generation (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])

if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
    CXXFLAGS="$CXXFLAGS -g -O0"
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    CXXFLAGS="$CXXFLAGS -03"
fi

#CPPFLAGS="$CFLAGS"
#AM_CLAGS="$CPPFLAGS"
#AM_CPPFLAGS="$CPPFLAGS"

###############################################################################


# Check for pthread stuff.
have_pthreads=no
AC_SEARCH_LIBS([pthread_create], [pthread], [have_pthreads=yes])
if test "x${have_pthreads}" = xyes; then
  AC_CHECK_HEADERS([pthread.h], [], [have_pthreads=no])
fi

if test "x${have_pthreads}" = xno; then
  AC_MSG_ERROR([
---------------------------------------
Unable to find pthread on this system.
pthread is required, build aborted.
---------------------------------------
  ])
fi
# end pthread stuff


# Check for openssl stuff.
have_openssl=no
AC_SEARCH_LIBS([BN_new], [crypto], [have_openssl=yes])
if test "x${have_openssl}" = xyes; then
  AC_CHECK_HEADERS([openssl/bn.h], [], [have_openssl=no])
fi

if test "x${have_openssl}" = xno; then
  AC_MSG_ERROR([
---------------------------------------
Unable to find openSSL on this system.
openSSL is required, build aborted.
---------------------------------------
  ])
fi
# end pthread stuff


# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h pthread.h time.h])
# Socket related header
AC_CHECK_HEADERS([sys/socket.h sys/types.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([floor gethostname memset sqrt socket bind])

AC_CONFIG_FILES([Makefile
                 src/base/Makefile
                 src/ssh/Makefile
                 src/server/Makefile
                 src/Makefile])
AC_OUTPUT

echo \
"---------------------------------------

${PACKAGE_NAME} Version ${PACKAGE_VERSION}

Prefix: ${prefix}
Compiler: ${CXX} ${CXXFLAGS}

Package features:
  Debug: ${debugit}
  
Now type 'make @<:@<target>@:>@'
  where the optional <target> is:
    all           - build all binaries
    install       - install everything

---------------------------------------"
