TESTS = test_runner
noinst_PROGRAMS = test_runner

LDADD = ../src/libburg.la ../lib/gmock/lib/libgmock.la ../lib/gmock/gtest/lib/libgtest.la $(INTLLIBS)
test_runner_LDFLAGS = -lconfig++ -lboost_thread -lcryptopp
test_runner_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/gmock/include/ -I$(top_srcdir)/lib/gmock/gtest/include/
test_runner_SOURCES = test_runner.cpp 
EXTRA_DIST = db.cfg
