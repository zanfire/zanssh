#! /bin/sh

make clean
autoreconf
./configure --enable-debug
