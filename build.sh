#!/bin/sh

CC=gcc
CFLAGS="-O3 -g -std=gnu99"

$CC $CFLAGS -o tripper2ch tripper.c
$CC $CFLAGS -DSHIICHAN -o trippershii tripper.c
$CC $CFLAGS -DWAKABA -o tripperc4 tripper.c
