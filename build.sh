#!/bin/sh

CC=gcc-4.2
CFLAGS="-Os -march=pentium -mtune=generic -std=gnu99"

$CC $CFLAGS -o tripper2ch tripper.c
$CC $CFLAGS -DSHIICHAN4K -o trippershii tripper.c
$CC $CFLAGS -DWAKABARC4 -o tripperc4 tripper.c
$CC $CFLAGS -o 2chdict tdict.c || true
