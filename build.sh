#!/bin/sh

CC=gcc
CFLAGS="-O3 -g -std=gnu99"

$CC $CFLAGS -o tripper2ch tripper.c
$CC $CFLAGS -DSHIICHAN4K -o trippershii tripper.c
$CC $CFLAGS -DWAKABARC4 -o tripperc4 tripper.c
$CC $CFLAGS -o 2chdict tdict.c || true
