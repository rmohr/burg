burg
====
Burg is a small extensible, flexible and easy to use authentication and authorization
framework.

Dependencies
------------

* gmock/gtest (included in [lib](lib))
* libcryptopp
* boost
* boost_threads
* libconfig++

Documentation
-------------

View the doxygen documentation as html:

```
firefox doc/html/index.html
```


View the doxygen documenatation as pdf:

```
evince doc/latex/refman.pdf
```

Installation
------------

```
mkdir -p m4 && autoreconf -fi 
./configure && make && make install
```

Tests
-----

The unit tests use gmock and gtest which are already included. To run the test
do the following after building the main project:

First you have to switch to the tests directory, otherwise all the unittest
included with gmock itself would be started too!

```
cd tests
make check
```

Usage
-----
The main headers are [burg/auth.h](include/burg/auth.h) and [burg/db.h](include/burg/db.h).
A simple username/password implementation can be used via
[burg/simple_auth.h](include/burg/simple_auth.h) and [burg/simple_db.h](include/burg/simple_db.h).

Examples
--------
A simple example can be found in [examples/example.cpp](examples/example.cpp).
To run it do the following after building the main project:

```
cd examples
./example roman hallo admin ../tests/db.cfg
```
