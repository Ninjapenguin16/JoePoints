#!/bin/sh

# This requires you to have the development packages for libmicrohttpd, sqlite, and json-c installed

make CFLAGS="-Wall -O2" LDFLAGS="" LIBS="-lmicrohttpd -lsqlite3 -ljson-c -lpthread -lm"