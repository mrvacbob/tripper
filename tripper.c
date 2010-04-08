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
 * Compiler required:
 * GCC 4.3 or above (Apple 4.2 or above) preferred.
 * Otherwise C99 is required and __BIG_ENDIAN__ or __LITTLE_ENDIAN__ must be defined.
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
# define always_inline __attribute__((always_inline))
#else
# define likely(x)   (x)
# define unlikely(x) (x)
# define always_inline inline
#endif

#ifdef SHIICHAN
# define OUTPUT_LEN 11
#elif WAKABA
# define OUTPUT_LEN 8
#else
# define OUTPUT_LEN 10
# undef MAX_TRIPCODE_LEN
#endif

#ifndef MAX_TRIPCODE_LEN
# define MAX_TRIPCODE_LEN 8
#endif

#define HTMLED_TRIPCODE_LEN (8*MAX_TRIPCODE_LEN)

#include "hash.c"
#include "crypt.c"

#ifdef CASE_SENSITIVE
# define ceq(a,b) (a)==(b)
#else
static uint8_t switchcase(uint8_t x)
{
    return ((x >= 'A') && (x <= 'Z')) ? (x+('a'-'A')) :
           ((x >= 'a') && (x <= 'z')) ? (x-('a'-'A')) : x;
}
static int ceq(uint8_t a, uint8_t b)
{
    return (a == b) ? 1 : a == switchcase(b);
}
#endif

static int strcontainsstr(const char *big, const char *small, int len, int slen)
{
    int i = 0, j;
redo_from_start:
    for (; i < (len - slen); i++)
        if (ceq(big[i], small[0]))
            goto more_tries;
    return 0;
more_tries:
    j = 1;
    for (i++; i < len; i++,j++) {
        if (j >= slen) return 1;
        if (!ceq(big[i],small[j]))
            goto redo_from_start;
    }
    return 0;
}

static char clean_salt(char i)
{
    if ((i < '.') || (i > 'z'))
        i = '.';
    if ((i >= ':') && (i <= '@'))
        i += 'A' - ':';
    else if ((i >= '[') && (i <= '`'))
        i += 'a' - '[';
    return i;
}

static char *tripcode_2ch(char *input, int length)
{
    char salt[2];

    if (length >= 2) {
        salt[0] = clean_salt(input[1]);
        salt[1] = (length > 2) ? clean_salt(input[2]) : 'H';
    } else {
        salt[0] = 'H';
        salt[1] = '.';
    }

    return crypt(input, salt) + 3;
}

static void tripcode_wakaba(uint8_t *input, char *buffer, int length)
{
    unsigned char hash[6];
    rc4(input,hash,length);
    base64(hash,buffer,sizeof(hash));
}

static void tripcode_shiichan(uint8_t *input, char *buffer, int length)
{
    unsigned int hash[5];
    sha1(input,hash,length);
    base64((const uint8_t*)hash,buffer,9);
}

static const uint8_t tripcode_inputs[94] = " \"$%&'()*+,-.!/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

static int htmlspecialchars(const char *trip, char *html, int length)
{
    int i, j;
    for (i = 0; i < length; i++) {
        char c = trip[i];
        switch (c) {
            case '<':
                html[j]   = '&';
                html[j+1] = 'l';
                html[j+2] = 't';
                html[j+3] = ';';
                j+=4;
                break;
            case '>':
                html[j]   = '&';
                html[j+1] = 'g';
                html[j+2] = 't';
                html[j+3] = ';';
                j+=4;
                break;
            case '&':
                html[j]   = '&';
                html[j+1] = 'a';
                html[j+2] = 'm';
                html[j+3] = 'p';
                html[j+4] = ';';
                j+=5;
                break;
            case '"':
                html[j]   = '&';
                html[j+1] = 'q';
                html[j+2] = 'u';
                html[j+3] = 'o';
                html[j+4] = 't';
                html[j+5] = ';';
                j+=6;
                break;
            case '\'':
                html[j]   = '&';
                html[j+1] = '#';
                html[j+2] = '0';
                html[j+3] = '3';
                html[j+4] = '9';
                html[j+5] = ';';
                j+=6;
                break;
            default:
                html[j++] = c;
        }
    }
    return j;
}

#if 0
//iteration-independent version of next_trip
//much slower but maybe useful for parallelizing
static void fill_count_for_trip(uint8_t *count, int len, unsigned step) {
    int i = len;
    while (i-- >= 0) {
        count[i] = step % 94;
        step /= 94;
    }
}

static unsigned trips_per_len(int len) {
    unsigned mul = 1;
    while (len--) mul *= 94;
    return mul;
}
#endif

static int next_trip(uint8_t *count, int len) {
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

static always_inline void
test_every_trip_of_length(int length, const char *search, int searchlen,
                          const uint8_t *salt, int saltlen, uint8_t *workspace)
{
    uint8_t count[MAX_TRIPCODE_LEN] = {0};

    do {
        char pre_html[MAX_TRIPCODE_LEN+1];
         int html_len;

        for (int i = 0; i < length; i++)
            pre_html[i] = tripcode_inputs[count[i]];

#ifdef SHIICHAN
        char buffer[12];
        html_len = htmlspecialchars(pre_html, workspace, length);
        memcpy(workspace+html_len, salt, saltlen);
        tripcode_shiichan(workspace, buffer, html_len+saltlen);
#elif defined(WAKABA)
        char buffer[10];
        html_len = htmlspecialchars(pre_html, workspace+1, length);
        memcpy(workspace+html_len+1, salt, saltlen);
        tripcode_wakaba(workspace, buffer, 1+html_len+saltlen);
#else
        char *buffer;
        html_len = htmlspecialchars(pre_html, workspace, length);
        workspace[html_len] = 0;
        buffer = tripcode_2ch(workspace, html_len);
#endif
        if (unlikely(strcontainsstr(buffer, search, OUTPUT_LEN, searchlen))) {
            buffer[OUTPUT_LEN] = pre_html[length] = '0';
            printf(
#if defined(SHIICHAN) || defined(WAKABA)
                   "##%s !%s\n"
#else
                   "#%s !%s\n"
#endif
                   , pre_html, buffer);
        }
    } while (next_trip(count, length));
}

static void terminatehandle(int unused)
{
    printf("Exiting...\n");
    exit(0);
}

int main(int argc, const char *argv[])
{
#if defined(SHIICHAN) || defined(WAKABA)
    if (argc < 3) return 1;
#else
    if (argc < 2) return 1;
#endif

    signal(SIGPIPE,terminatehandle);
    signal(SIGTERM,terminatehandle);
    signal(SIGINT,terminatehandle);

    const uint8_t *salt = NULL;
    int saltlen = 0, searchlen = 0;
    int i;

    searchlen = strlen(argv[1]);

#ifdef SHIICHAN
# define shaworklen (HTMLED_TRIPCODE_LEN+448)
    uint8_t saltbuf[448];
    uint8_t work[shaworklen + (64 - (shaworklen%64))];
    saltlen=448;
    salt = saltbuf;

    int f = open(argv[2], O_RDONLY);
    if (f == -1) {
        perror("salt read failed");
        exit(1);
    }
    read(f, saltbuf, 448);
    close(f);
#elif WAKABA
    uint8_t work[1+HTMLED_TRIPCODE_LEN+saltlen];
    saltlen = strlen(argv[2]);
    salt = argv[2];
    work[0] = 't';
#else
    uint8_t work[HTMLED_TRIPCODE_LEN];
    init_des();
#endif

    for (i = 1; i <= MAX_TRIPCODE_LEN; i++)
        test_every_trip_of_length(i, argv[1], searchlen, salt, saltlen, work);
    return 0;
}
