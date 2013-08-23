# Copyright (C) 2013 Roman Mohr - <roman@fenkhucer.at>

AC_PREREQ([2.59])
AC_INIT([burg], [0.1.0], [roman@fenkhuber.at])
AC_CONFIG_SRCDIR([include/remote.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.

# Checks for header files.

# Check for boost
AX_BOOST_BASE([1.36.0], [], [AC_MSG_ERROR(
                              [Please install boost >= 1.36.0 (regex,
                               filesystem, system])])
#AX_BOOST_REGEX
#AX_BOOST_FILESYSTEM
#AX_BOOST_SYSTEM

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.

AC_CONFIG_FILES([include/Makefile Makefile tests/Makefile src/Makefile])
AC_CONFIG_SUBDIRS([lib/gmock])
AC_OUTPUT
