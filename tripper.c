/*
 * Copyright (c) 2004-2010 mrvacbob <mrvacbob@users.noreply.github.com>
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
 * To build: make
 *
 * Output:
 *  #blah !XXXXXXXXXX
 *  Append #blah to your name when posting to get the printed tripcode.
 *
 * Compiler required: Clang (C99 or later).
 */

/*
 * Todo:
 *  - iterate over SJIS strings instead of ASCII
 *  - for DES, iterate in an order that requires fewer des_setkey() calls
 *  - attempt to remove all variable-length arrays
 *    (they inhibit various gcc optimizations compared to malloc)
 *  - in strcontainsstr, convert both input strings to lowercase instead of using ceq()
 *    (this should be faster)
 */

#define crypt __crypt
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
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

#ifdef SHIICHAN
# define shaworklen (HTMLED_TRIPCODE_LEN+448)
# define WORKLEN    (shaworklen + (64 - (shaworklen%64)))
#elif !defined(WAKABA)
# define WORKLEN    HTMLED_TRIPCODE_LEN
#endif

static atomic_int g_interrupted = 0;

#if defined(SHIICHAN) || defined(WAKABA)
# include "hash.c"
#endif
#if !defined(SHIICHAN) && !defined(WAKABA)
# include "crypt.c"
#endif

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
    for (; i <= (len - slen); i++)
        if (ceq(big[i], small[0]))
            goto more_tries;
    return 0;
more_tries:
    for (j = 1; j < slen; j++) {
        i++;
        if (i >= len || !ceq(big[i], small[j]))
            goto redo_from_start;
    }
    return 1;
}

#if !defined(SHIICHAN) && !defined(WAKABA)
static uint8_t clean_salt(uint8_t i)
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
    uint8_t salt[2];

    if (length >= 2) {
        salt[0] = clean_salt(input[1]);
        salt[1] = (length > 2) ? clean_salt(input[2]) : 'H';
    } else {
        salt[0] = 'H';
        salt[1] = '.';
    }

    return crypt(input, (const char *)salt) + 3;
}
#endif

#if defined(WAKABA)
static void tripcode_wakaba(uint8_t *input, char *buffer, int length)
{
    unsigned char hash[6];
    rc4(input,hash,length);
    base64(hash,buffer,sizeof(hash));
}
#endif

#if defined(SHIICHAN)
static void tripcode_shiichan(uint8_t *input, char *buffer, int length)
{
    uint32_t hash[5];
    sha1(input,hash,length);
    base64((const uint8_t*)hash,buffer,9);
}
#endif

static const uint8_t tripcode_inputs[94] = " \"$%&'()*+,-.!/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

static int htmlspecialchars(const char *trip, uint8_t *html, int length)
{
    int i, j = 0;
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

static void
test_every_trip_of_length(int length, const char *search, int searchlen,
                          const uint8_t *salt, int saltlen)
{
#pragma omp parallel for schedule(static)
    for (int first = 0; first < 94; first++) {
        if (atomic_load_explicit(&g_interrupted, memory_order_relaxed)) continue;
#if !defined(SHIICHAN) && !defined(WAKABA)
        if (!des_initialised) des_init();
#endif
#ifdef SHIICHAN
        _Alignas(uint32_t) uint8_t workspace[WORKLEN];
#elif defined(WAKABA)
        uint8_t workspace[1+HTMLED_TRIPCODE_LEN+saltlen];
        workspace[0] = 't';
#else
        uint8_t workspace[WORKLEN];
#endif
        uint8_t count[MAX_TRIPCODE_LEN] = {0};
        count[0] = first;

        do {
            if (unlikely(atomic_load_explicit(&g_interrupted, memory_order_relaxed))) break;
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
            buffer = tripcode_2ch((char *)workspace, html_len);
#endif
            if (unlikely(strcontainsstr(buffer, search, OUTPUT_LEN, searchlen))) {
                buffer[OUTPUT_LEN] = pre_html[length] = 0;
#pragma omp critical
                printf(
#if defined(SHIICHAN) || defined(WAKABA)
                       "##%s !%s\n"
#else
                       "#%s !%s\n"
#endif
                       , pre_html, buffer);
            }
        } while (next_trip(count + 1, length - 1));
    }
}

static void terminatehandle(int unused)
{
    static const char msg[] = "\nExiting...\n";
    atomic_store_explicit(&g_interrupted, 1, memory_order_relaxed);
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    (void)unused;
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
    uint8_t saltbuf[448];
    saltlen=448;
    salt = saltbuf;

    int f = open(argv[2], O_RDONLY);
    if (f == -1) {
        perror("salt read failed");
        exit(1);
    }
    if (read(f, saltbuf, 448) != 448) {
        perror("salt read failed");
        exit(1);
    }
    close(f);
#elif WAKABA
    saltlen = strlen(argv[2]);
    salt = (const uint8_t *)argv[2];
#endif

    for (i = 1; i <= MAX_TRIPCODE_LEN; i++) {
        test_every_trip_of_length(i, argv[1], searchlen, salt, saltlen);
        if (atomic_load_explicit(&g_interrupted, memory_order_relaxed)) break;
    }
    return 0;
}
