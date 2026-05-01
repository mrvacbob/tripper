CC     = cc
CFLAGS = -O2 -g -std=gnu99 -Wall
SRCS   = tripper.c hash.c crypt.c

all: tripper2ch trippershii tripperc4

tripper2ch: $(SRCS)
	$(CC) $(CFLAGS) -o $@ tripper.c

trippershii: $(SRCS)
	$(CC) $(CFLAGS) -DSHIICHAN -o $@ tripper.c

tripperc4: $(SRCS)
	$(CC) $(CFLAGS) -DWAKABA -o $@ tripper.c

clean:
	rm -rf tripper2ch trippershii tripperc4 *.dSYM

.PHONY: all clean
