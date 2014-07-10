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


TESTS = burg
noinst_PROGRAMS = burg

LIBS = ../src/libburg.la ../lib/gmock/lib/libgmock.la ../lib/gmock/gtest/lib/libgtest.la  $(INTLLIBS) 
CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/gmock/include/ -I$(top_srcdir)/lib/gmock/gtest/include/

burg_SOURCES = burg.cpp mock.h

if HAVE_CRYPTO
crypto_SOURCES = crypto.cpp
TESTS += crypto
noinst_PROGRAMS += crypto
endif

if HAVE_LIBCONFIG
libconfig_SOURCES = libconfig.cpp
TESTS += libconfig
noinst_PROGRAMS += libconfig
endif

if HAVE_PAM
pam_SOURCES = pam.cpp
TESTS += pam
noinst_PROGRAMS += pam
endif

EXTRA_DIST = db.cfg
