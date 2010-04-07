/*
 * Copyright (c) 2004-2010 Alexander Strange <astrange@ithinksw.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* 
 * Brute-force tripcode finder, for 2channel boards.
 * Will work with restrictions on Wakaba/Wakaba-ZERO/Kareha/Shiichan/Futallaby/Futaba/Electron/Etc.
 * Tripcode output containing <>"'!#,& may not work on some (incorrect) boards.
 *
 * To build: ./build.sh
 *  
 * Output:
 *  #blah !XXXXXXXXXX
 *  Append #blah to your name when posting to get the printed tripcode.
 *
 * Todo:
 *  check higher-ascii/SJIS tripcode inputs
 */

#define crypt __crypt
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#undef crypt

#ifdef __GNUC__
# define likely(x)   __builtin_expect(x,1)
# define unlikely(x) __builtin_expect(x,0)
#else
# define likely(x)   (x)
# define unlikely(x) (x)
#endif

#ifdef SHIICHAN4K
# include "hash.c"
# define OUTPUT_LEN 11
#elif WAKABARC4
# include "hash.c"
# define OUTPUT_LEN 8
#else
# include "crypt.c"
# define OUTPUT_LEN 10
# undef MAX_TRIPCODE_LEN
#endif

#ifndef MAX_TRIPCODE_LEN
# define MAX_TRIPCODE_LEN 8
#endif

#define HTMLED_TRIPCODE_LEN (8*MAX_TRIPCODE_LEN)

#ifdef CASE_SENSITIVE
# define ceq(a,b) unlikely((a)==(b))
#else
static inline unsigned char switchcase(unsigned char x) {return ((x >= 'A') && (x <= 'Z')) ? (x+('a'-'A')) : ((x >= 'a') && (x <= 'z')) ? (x-('a'-'A')) : x;}
static inline unsigned char _ceq(unsigned char a, unsigned char b) {return (a == b) ? : a == switchcase(b);}
# define ceq(a, b) (unlikely(_ceq(a,b)))
#endif

static inline unsigned char strcontainsstr(const unsigned char * big,const char * small, unsigned char len, unsigned char slen)
{
	unsigned char i=0, i2=0;
	if (slen == 0) return 1; 
redo_from_start: 
		for (; i < len; i++) if (ceq(big[i],small[0])) goto more_tries;
	return 0;
more_tries: 
		i2 = 1;
	for (i++; i < len; i++,i2++) {
		if (!ceq(big[i],small[i2])) {
			if (slen == i2) return 1;
			else if (ceq(big[i],small[0])) goto more_tries;
			else goto redo_from_start;
		}
	}
	return 0;
}

#ifndef SHIICHAN4K
#ifndef WAKABARC4
static inline unsigned char
tripsaltclean(unsigned char i)
{
    if ((i < '.') || (i > 'z'))
        i = '.';
    if ((i >= ':') && (i <= '@'))
        i += 'A' - ':';
    else if ((i >= '[') && (i <= '`'))
        i += 'a' - '[';
    return i;
}

static inline unsigned char *
tripcode_2ch(unsigned char *input, unsigned int ilen)
{
    char salt[2];
	
    if (ilen >= 2) {
        salt[0] = tripsaltclean(input[1]);
        salt[1] = (ilen > 2)?tripsaltclean(input[2]):'H';
    } else {salt[0] = 'H'; salt[1] = '.';}
	
    return (unsigned char*)crypt((char*)input, salt) + 3;
}
#else
static inline void
tripcode_wakaba(unsigned char *input,unsigned char *buffer, unsigned int ilen)
{
	unsigned char hash[6];
    rc4(input,hash,ilen);
    base64(hash,buffer,6);
}
#endif
#else
static inline void
tripcode_shiichan(unsigned char *input,unsigned char *buffer, unsigned int ilen)
{
    unsigned int hash[5];
    sha1(input,ilen,hash);
    base64((const unsigned char *)hash,buffer,9);
}
#endif

static const unsigned char tripcode_inputs[94] = " \"$%&'()*+,-.!/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

static inline int htmlspecialchars(unsigned char *trip, unsigned char *htmled, unsigned char ilen)
{
    int i=0,  i2=0;
    for (;i < ilen; i++) {
        unsigned char c = trip[i];
        switch (c) {
			case '<':
				htmled[i2] = '&'; 
				htmled[i2+1] = 'l'; 
				htmled[i2+2] = 't'; 
				htmled[i2+3] = ';';
				i2+=4;
				break;
			case '>':
				htmled[i2] = '&'; 
				htmled[i2+1] = 'g'; 
				htmled[i2+2] = 't'; 
				htmled[i2+3] = ';';
				i2+=4;
				break;
			case '&':
				htmled[i2] = '&'; 
				htmled[i2+1] = 'a'; 
				htmled[i2+2] = 'm'; 
				htmled[i2+3] = 'p'; 
				htmled[i2+4] = ';';
				i2+=5;
				break;
			case '"':
				htmled[i2] = '&'; 
				htmled[i2+1] = 'q'; 
				htmled[i2+2] = 'u'; 
				htmled[i2+3] = 'o'; 
				htmled[i2+4] = 't'; 
				htmled[i2+5] = ';';
				i2+=6;
				break;
			case '\'':
				htmled[i2] = '&'; 
				htmled[i2+1] = '#'; 
				htmled[i2+2] = '0'; 
				htmled[i2+3] = '3'; 
				htmled[i2+4] = '9'; 
				htmled[i2+5] = ';';
				i2+=6;
				break;
			default: htmled[i2] = c; i2++;
        }
	}
    return i2;
}

//iteration-independent version of next_trip
//much slower but useful for parallelizing maybe
static inline void fill_count_for_trip(unsigned char *count, unsigned len, unsigned step) {
	int i = len;
	while (i-- >= 0) {
		count[i] = step % 94;
		step /= 94;
	}
}
 
 
static inline unsigned trips_per_len(unsigned len) {
 // trips = 94**len
 unsigned mul=1;
 while (len--) mul *= 94;
 return mul;
} 

static inline int next_trip(unsigned char *count, unsigned len) {
    int i = len;
    
    while (i-- > 0) {
        if (count[i] == sizeof(tripcode_inputs)-1) {
            count[i] = 0; //carry
        } else {
            count[i]++;
            return 1;
        }
    }
    return 0; //ran out of trips
}

static inline void
testeverytripoflength(unsigned char len,const char * search, unsigned char searchlen, unsigned char *workspace,const char * salt, unsigned int saltlen)
{
    unsigned char count[MAX_TRIPCODE_LEN] = {0};

    do {        
		unsigned char len2, i;
        unsigned char prehtml[MAX_TRIPCODE_LEN+1];
        for (i=0; i < len; i++) prehtml[i] = tripcode_inputs[count[i]];
        
#ifdef SHIICHAN4K
        unsigned char buffer[12];
        len2 = htmlspecialchars(prehtml, workspace, len);
        memcpy(workspace+len2,salt,saltlen);
        tripcode_shiichan(workspace, buffer, len2+saltlen);
#elif WAKABARC4
        unsigned char buffer[10];
        len2 = htmlspecialchars(prehtml, workspace+1, len);
        memcpy(workspace+1+len2,salt,saltlen);
        tripcode_wakaba(workspace, buffer, 1+len2+saltlen);
#else
        unsigned char *buffer;
        len2 = htmlspecialchars(prehtml, workspace,len);
        workspace[len2]='\0';
        buffer = tripcode_2ch(workspace, len2);
#endif
        if (unlikely(strcontainsstr(buffer, search, OUTPUT_LEN, searchlen))) {
			buffer[OUTPUT_LEN] = prehtml[len]='\0';
            printf(
#if defined(SHIICHAN4K) || defined(WAKABARC4)
				   "##%s !%s\n"
#else
				   "#%s !%s\n"
#endif
				   , prehtml, buffer);
        }
    } while (next_trip(count, len));
}

static void terminatehandle(int unused)
{
	printf("Exiting...\n");
	exit(0);
}

int
main(int argc, const char *argv[])
{
    unsigned int i, searchlen;const char *salt; unsigned saltlen;
	signal(SIGPIPE,terminatehandle);
	signal(SIGTERM,terminatehandle);
	signal(SIGINT,terminatehandle);
	setlinebuf(stdout);

#ifdef SHIICHAN4K
# define shaworklen (HTMLED_TRIPCODE_LEN+448)
	if (argc<3) return 1;
	unsigned char salta[448]; salt=(char*)salta;
	unsigned char work[shaworklen + (64 - (shaworklen%64))]; saltlen=448;
    int f = open(argv[2],O_RDONLY); if (f==-1) {perror("salt read failed"); exit(1);} read(f,salta,448); close(f);
#elif WAKABARC4
	if (argc<3) return 1;
	saltlen = strlen(argv[2]);
	unsigned char work[1+HTMLED_TRIPCODE_LEN+saltlen];
    work[0] = 't';
	salt = argv[2];
#else
	if (argc<2) return 1;
	unsigned char work[HTMLED_TRIPCODE_LEN];
    init_des(); salt=NULL; saltlen = 0;
#endif
	searchlen = strlen(argv[1]);
    for (i = 1; i <= MAX_TRIPCODE_LEN; i++)
        testeverytripoflength(i, argv[1], searchlen, work, salt, saltlen);
    return 0;
}
