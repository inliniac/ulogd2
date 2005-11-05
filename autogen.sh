#!/bin/sh

aclocal
libtoolize -c --force 
automake -c --add-missing
autoconf
