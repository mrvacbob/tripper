/* Brute-force tripcode finder, for 2channel boards.
* Will work with restrictions on Wakaba/Wakaba-ZERO/Kareha/Shiichan/Futallaby/Futaba/Electron/Etc.
* Tripcode output containing <>"'!#,& may not work.
*
* To build: build.sh
*  
* Output:
* #blah !XXXXXXXXXX
* Append #blah to your name when posting to get the printed tripcode.
* Todo:
*  check higher-ascii/SJIS tripcode inputs
*  $Id$ Alexander Strange, astrange@ithinksw.com, http://astrange.ithinksw.net/
*  Shiichan: http://shii.org/shiichan
*  Kareha: http://wakaba.c3.cx/
*/
#define crypt notmycrypt
#include <unistd.h>
#undef crypt
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <stdlib.h>
#include <signal.h>

#ifdef SHIICHAN4K
#include "sha1.c"
#include "base64.c"
#define OUTPUT_LEN 12
#elif WAKABARC4
#include "rc4.c"
#include "base64.c"
#define OUTPUT_LEN 9
#else
#include "crypt.c"
#define OUTPUT_LEN 11
#endif

#ifdef __GNUC__
#define likely(x) __builtin_expect(x,1)
#define unlikely(x) __builtin_expect(x,0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#ifdef CASE_SENSITIVE
#define ceq(a,b) ((a)==(b))
#else
static inline unsigned char sc(unsigned char x) {return ((x >= 'A') && (x <= 'Z')) ? (x+('a'-'A')) : ((x >= 'a') && (x <= 'z')) ? (x-('a'-'A')) : x;} // switch case
static inline unsigned char ceq(unsigned char a, unsigned char b) {unsigned char r = unlikely(a==b); return r ? r : a == sc(b);}
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
static unsigned char
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

static unsigned char *
tripcode_2ch(unsigned char *input, unsigned int ilen)
{
    char            salt[2];
	
    if ((ilen >= 2)) {
        salt[0] = tripsaltclean(input[1]);
        salt[1] = (ilen > 2)? tripsaltclean(input[2]):'H';
    } else {salt[0] = 'H'; salt[1] = '.';}
	
    return (unsigned char*)crypt((char*)input, salt) + 3;
}
#else
static void
tripcode_wakaba(unsigned char *input,unsigned char *buffer, unsigned int ilen)
{
	unsigned char hash[6];
    rc4(input,hash,ilen);
    b64rc4(hash,buffer);
}
#endif
#else
static void
tripcode_shiichan(unsigned char *input,unsigned char *buffer, unsigned int ilen)
{
    unsigned long hash[5];
    sha1(input,ilen,hash);
    b64sha((unsigned char*)hash,buffer);
}
#endif

static const unsigned char tripcode_inputs[94] = " \"$%&'()*+,-.!/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

static unsigned int htmlspecialchars(unsigned char *tripindexes, unsigned char *htmled, unsigned char ilen)
{
    unsigned char i=0; int i2=0;
    for (;i < ilen; i++) {
        unsigned char c = tripcode_inputs[tripindexes[i]];
        switch (c) {
			case '<':
				htmled[i2++] = '&'; 
				htmled[i2++] = 'l'; 
				htmled[i2++] = 't'; 
				htmled[i2++] = ';';
				break;
			case '>':
				htmled[i2++] = '&'; 
				htmled[i2++] = 'g'; 
				htmled[i2++] = 't'; 
				htmled[i2++] = ';';
				break;
			case '&':
				htmled[i2++] = '&'; 
				htmled[i2++] = 'a'; 
				htmled[i2++] = 'm'; 
				htmled[i2++] = 'p'; 
				htmled[i2++] = ';';
				break;
			case '"':
				htmled[i2++] = '&'; 
				htmled[i2++] = 'q'; 
				htmled[i2++] = 'u'; 
				htmled[i2++] = 'o'; 
				htmled[i2++] = 't'; 
				htmled[i2++] = ';';
				break;
			case '\'':
				htmled[i2++] = '&'; 
				htmled[i2++] = '#'; 
				htmled[i2++] = '0'; 
				htmled[i2++] = '3'; 
				htmled[i2++] = '9'; 
				htmled[i2++] = ';';
				break;
			default: htmled[i2++] = c;
        }
	}
    return i2;
}

static void fill_count(unsigned char *count, unsigned len, unsigned step) {
	int i = len;
	while (i-- >= 0) {
		count[i] = step % 94;
		step /= 94;
	}
}

static unsigned trips_per_len(unsigned len) {
	// trips = 94**len
	unsigned mul=1;
	while (len--) mul *= 94;
	return mul;
}

static void
testeverytripoflength(unsigned char len,const char * search, unsigned char searchlen, unsigned char *workspace,const char * salt, unsigned int saltlen)
{
	unsigned int trips = trips_per_len(len), i;
	
    for (i = 0; i < trips; i++) {
		unsigned char count[8];
		unsigned char len2;
		fill_count(count, len, i);
#ifdef SHIICHAN4K
        unsigned char buffer[12];
        len2 = htmlspecialchars(count, workspace, len);
        memcpy(workspace+len2,salt,saltlen);
        tripcode_shiichan(workspace, buffer, len2+saltlen);
#elif WAKABARC4
        unsigned char buffer[10];
        len2 = htmlspecialchars(count, workspace+1, len);
        memcpy(workspace+1+len2,salt,saltlen);
        tripcode_wakaba(workspace, buffer, 1+len2+saltlen);
#else
        unsigned char *buffer;
        len2 = htmlspecialchars(count, workspace,len);
        workspace[len2]='\0';
        buffer = tripcode_2ch(workspace, len2);
#endif
        if (strcontainsstr(buffer, search, OUTPUT_LEN, searchlen)) {
            unsigned char tripin[9],j;
            for (j=0; j < len; j++) tripin[j] = tripcode_inputs[count[j]];
			buffer[OUTPUT_LEN-1] = tripin[len]='\0';
            printf(
#if 1
#if defined(SHIICHAN4K) || defined(WAKABARC4)
				   "##%s !%s\n"
#else
				   "#%s !%s\n"
#endif
#else
				   ""
#endif
				   , tripin, buffer);
        }
    }// while (!advance(count, len));
}

static void terminatehandle(int unused)
{
	printf("Exiting...\n");
	exit(0);
}

int
main(int argc, const char *argv[])
{
    int i; int searchlen;const char *salt; unsigned saltlen;
	signal(SIGPIPE,terminatehandle);
	signal(SIGTERM,terminatehandle);
	signal(SIGINT,terminatehandle);
//	argc=3; argv=(const char*[]){"","lain","/Library/WebServer/Documents/shiichan/salt.cgi"};
	setlinebuf(stdout);
#ifdef SHIICHAN4K
#define shaworklen (8*6+448)
	if (argc<3) return 1;
	unsigned char salta[448]; salt=(char*)salta;
	unsigned char work[shaworklen + (64 - (shaworklen%64))]; saltlen=448;
    int f = open(argv[2],O_RDONLY); if (f==-1) {perror("salt read failed"); exit(1);} read(f,salta,448); close(f);
#elif WAKABARC4
	if (argc<3) return 1;
	saltlen = strlen(argv[2]);
	unsigned char work[1+8*6+saltlen];
    work[0] = 't';
	salt = argv[2];
#else
	if (argc<2) return 1;
	unsigned char work[8*6];
    init_des(); salt=NULL; saltlen = 0;
#endif
	searchlen = strlen(argv[1]);
		//double d = the_time();
    for (i = 1; i <= 8; i++)
        testeverytripoflength(i, argv[1], searchlen, work, salt, saltlen);
    return 0;
}
