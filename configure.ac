#
# Copyright 2013, Roman Mohr <roman@fenkhuber.at>
#
# This file is part of burg.
#
# Burg is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Burg is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with burg.  If not, see <http://www.gnu.org/licenses/>.
#

AC_PREREQ([2.59])
AC_INIT([burg], [0.1.0], [roman@fenkhuber.at])
AC_CONFIG_SRCDIR([include/burg/auth.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([crypt.h])
AC_CHECK_HEADERS([security/pam_appl.h])

PKG_CHECK_MODULES([LIBCONFIGXX], [libconfig++ >= 1.3],[have_libconfig=true],
                  [have_libconfig=false])
AM_CONDITIONAL([HAVE_LIBCONFIG], [test x$have_libconfig = xtrue])

PKG_CHECK_MODULES([CRYPTOPP], [libcrypto++ >= 5.6.0],[have_cryptopp=true],
                  [PKG_CHECK_MODULES([CRYPTOPP], [cryptopp >= 5.6.0],
                                     [have_cryptopp=true],
                                     [have_cryptopp=false]) ])
AM_CONDITIONAL([HAVE_CRYPTO], [test x$have_cryptopp = xtrue])

AC_SEARCH_LIBS(pam_start, pam, [have_pam=true], [have_pam=false])
AM_CONDITIONAL([HAVE_PAM], [test x$have_pam = xtrue])

# Check for boost
AX_BOOST_BASE([1.36.0], [], [AC_MSG_ERROR(
                              [Please install boost >= 1.36.0 (thread)])])
AX_BOOST_THREAD

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([strdup])

AC_CONFIG_FILES([include/Makefile Makefile tests/Makefile src/Makefile \
                 examples/Makefile])
AC_CONFIG_SUBDIRS([lib/gmock])

AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_OUTPUT
