burg
====
Burg is a flexible, easy to use and extend authentication and authorization
framework.

Dependencies
------------

* gmock/gtest (included in *lib*)
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
./configure
make
make install
```

Tests
-----

The unit tests use gmock and gtest which are already included. To run the test
do the following after building the main project:

```
cd tests
make check
```

Usage
-----
The main headers are **burg/auth.h** and **burg/db.h**.
A simple username/password implementation can be used via
**burg/simple_auth.h** and **burg/simple_db.h**.

Examples
--------
A simple example can be found in **examples/example.cpp**.
To run it do the following after building the main project:

```
cd examples
./example roman hallo admin ../tests/db.cfg
```
