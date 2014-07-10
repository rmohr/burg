burg
====

[![Build Status](https://travis-ci.org/rmohr/burg.svg?branch=master)](https://travis-ci.org/rmohr/burg)

Burg is a small extensible, flexible and easy to use authentication and authorization
framework.

Dependencies
------------

* boost
* boost_threads
* gmock/gtest (included in [lib](lib))
* libconfig++ (optional)
* libcryptopp (optional)
* pam (optional)

Debian/Ubuntu
=============

```
sudo apt-get install libconfig++-dev libboost-dev libboost-thread-dev autoconf-archive libpam0g-dev
```

Fedora
======

```
yum install pam-devel libconfig-devel boost-devel boost-thread cryptopp-devel
```

Documentation
-------------

The documentation is hosted on [rmohr.github.io/burg](https://rmohr.github.io/burg/).

Installation
------------

```
mkdir -p m4 && autoreconf -fi 
./configure && make && make install
```

Tests
-----

The unit tests use gmock and gtest which are already included. To run the tests,
execute

```
make -C tests && make -C tests check-TESTS
```

Usage
-----
The main headers are [burg/auth.h](include/burg/auth.h) and [burg/db.h](include/burg/db.h).
A simple username/password implementation can be used via
[burg/simple_auth.h](include/burg/simple_auth.h) and [burg/simple_db.h](include/burg/simple_db.h).

Examples
--------
A simple example can be found in [examples/example.cpp](examples/example.cpp).
It requires *libconfig++* and *libcryptopp*. To run it, execute

```
make -C examples
./examples/example roman hallo admin ./tests/db.cfg
```
