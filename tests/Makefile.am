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


TESTS = pam libconfig burg crypto
noinst_PROGRAMS = pam libconfig burg crypto

LIBS = ../src/libburg.la ../lib/gmock/lib/libgmock.la ../lib/gmock/gtest/lib/libgtest.la  $(INTLLIBS) 
CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/gmock/include/ -I$(top_srcdir)/lib/gmock/gtest/include/

burg_SOURCES = burg.cpp mock.h
crypto_SOURCES = crypto.cpp mock.h
libconfig_SOURCES = libconfig.cpp
pam_SOURCES = pam.cpp
EXTRA_DIST = db.cfg
