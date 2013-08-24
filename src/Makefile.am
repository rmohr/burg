#bin_PROGRAMS = rserver rclient
#rserver_SOURCES =  server.cpp simple_auth.cpp simple_db.cpp util.cpp
#AM_LDFLAGS = -lconfig++ -lboost_thread -lcryptopp
#rclient_SOURCES=  client.cpp

lib_LTLIBRARIES = libburg.la

libburg_la_LDFLAGS = -version-info 1:0:0

libburg_la_CPPFLAGS = -I$(top_srcdir)/include/burg

libburg_la_SOURCES = simple_auth.cpp simple_db.cpp util.cpp
