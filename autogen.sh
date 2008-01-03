#!/bin/sh

aclocal
autoheader
libtoolize -c --force 
automake -c --add-missing
autoconf
