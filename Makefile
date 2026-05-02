CC     = cc
CFLAGS = -O2 -g -std=gnu11 -Wall
SRCS   = tripper.c hash.c crypt.c

ifdef OPENMP
CFLAGS  += -Xpreprocessor -fopenmp -I/opt/local/include
LDFLAGS += -L/opt/local/lib -lomp
endif

all: tripper2ch trippershii tripperc4

tripper2ch: $(SRCS)
	$(CC) $(CFLAGS) -o $@ tripper.c $(LDFLAGS)

trippershii: $(SRCS)
	$(CC) $(CFLAGS) -DSHIICHAN -o $@ tripper.c $(LDFLAGS)

tripperc4: $(SRCS)
	$(CC) $(CFLAGS) -DWAKABA -o $@ tripper.c $(LDFLAGS)

clean:
	rm -rf tripper2ch trippershii tripperc4 *.dSYM

.PHONY: all clean
