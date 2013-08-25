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


noinst_PROGRAMS = example

LDADD = ../src/libburg.la $(INTLLIBS)
example_LDFLAGS = -lconfig++ -lboost_thread -lcryptopp
example_CPPFLAGS = -I$(top_srcdir)/include
example_SOURCES = example.cpp
