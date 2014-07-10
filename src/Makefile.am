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


#bin_PROGRAMS = rserver rclient
#rserver_SOURCES =  server.cpp simple_auth.cpp simple_db.cpp util.cpp
#AM_LDFLAGS = -lconfig++ -lboost_thread -lcryptopp
#rclient_SOURCES=  client.cpp

lib_LTLIBRARIES = libburg.la

libburg_la_LDFLAGS = -version-info 1:0:0 $(LIBCONFIGXX_LIBS) $(CRYPTOPP_LIBS) $(BOOST_THREAD_LIB)

libburg_la_CPPFLAGS = -I$(top_srcdir)/include/burg

libburg_la_SOURCES =  libconfig.cpp simple_auth.cpp simple_store.cpp util.cpp util.h

if HAVE_PAM
libburg_la_LDFLAGS += -lpam
libburg_la_SOURCES += pam.cpp
endif
