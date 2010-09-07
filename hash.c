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
 * RC4, SHA1, Base64 implementations
 *
 * RC4    - from Wakaba (http://wakaba.c3.cx/s/web/wakaba_kareha) converted from Perl
 * SHA1   - http://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
 * Base64 - http://tools.ietf.org/html/rfc4648
 *
 * This file is included from tripper.c.
 *
 * Notes:
 *  Anyone who writes SHA1 with a fully unrolled loop (spotted in OpenSSL, darcs, etc.) is in a state of sin.
 *  gcc compiles rc4() badly on x86 and seems to generate unnecessary sign extensions.
 *  The loop in sha1_block() should be partially unrolled to avoid constantly testing the range of 'i'.
 *  The placement of setting 'temp' in sha1 is different from the reference and may or may not be better.
 */

/* 
 * Todo:
 * - see FIXME in sha1
 * - check this code for OpenCL suitability
 */

static void base64(const uint8_t *hash, char *buffer, int length)
{
    static const uint8_t a[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for (int i = 0; i < (length/3); i++) {
        int i3 = i*3, i4 = i*4;
        unsigned bits = hash[i3]<<16 | hash[i3+1]<<8 | hash[i3+2];

        buffer[i4+0] = a[(bits>>18) % 64];
        buffer[i4+1] = a[(bits>>12) % 64];
        buffer[i4+2] = a[(bits>>6)  % 64];
        buffer[i4+3] = a[bits       % 64];
    }
}

#define swap(type, a, b) {type t = (a); (a) = (b); (b) = t;}
static void rc4(const uint8_t *input, uint8_t output[6], int length)
{
    uint8_t S[256];
    uint8_t j, k;
    int i, i2;

    for (i = 0; i < 256; i++)
        S[i] = i;

    for (i = 0; i < 256; i++) {
        j = j + S[i] + input[i2++];
        swap(uint8_t, S[i], S[j]);
        if (i2 == length) i2 = 0;
    }
    for (i = 0, i2 = 0, j = 0; i < 256; i++) {
        j += S[i];
        swap(uint8_t, S[i], S[j]);
    }
    for (i = 0; i < 6; i++) {
        j += S[i];

        k = S[i] + S[j];
        output[i] = S[k];
        swap(uint8_t, S[i], S[j]);
    }
}

static uint32_t rotate(uint32_t i, int n) { return i << n | i >> (32 - n); }
static void sha1_block(void *input, unsigned h[5])
{
    unsigned a,b,c,d,e,f,k;
    unsigned *block = input;
    int i;

    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    for (i = 0; i < 80; i++) {
        unsigned temp;

        // FIXME this can be lifted out of loop I think (would cause more memory reads but from L1)
        if (i < 16) {
            temp = block[i];
        } else {
            // FIXME the X in i-X can be increased with a different algorithm
            // which might allow SIMD
            // http://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1/
            temp = block[(i-3)%16] ^ block[(i-8)%16] ^ block[(i-14)%16] ^ block[i%16];
            temp = rotate(temp, 1);
            block[i%16] = temp;
        }

        if (i < 20) {
            f = d^(b&(c^d));
            k = 0x5A827999;
        } else if (i < 40) {
            f = b^c^d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b&c)^(b&d)^(c&d);
            k = 0x8F1BBCDC;
        } else {
            f = b^c^d;
            k = 0xCA62C1D6;
        }

        e = d;
        d = c;
        c = rotate(b, 30);
        b = a;
        a = rotate(a, 5) + e + f + k + temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

static unsigned bswap_32(unsigned n)
{
#ifdef __GNUC__
    return __builtin_bswap32(n);
#else
    n = ((n<<8)&0xFF00FF00) | ((n>>8)&0x00FF00FF);
    n = (n>>16) | (n<<16);
    return n;
#endif
}

static unsigned le_bswap32(unsigned n)
{
#ifndef __BIG_ENDIAN__
    n = bswap_32(n);
#endif
    return n;
}

static void le_bswap_array(void *a, int words)
{
#ifndef __BIG_ENDIAN__
    unsigned *word = a;
    while (words--) {
        *word = bswap_32(*word);
        word++;
    }
#endif
}

// It's assumed that input is allocated a multiple of 64 bytes and we can overwrite it
static void sha1(uint8_t *input, unsigned *buffer, int length)
{
    unsigned h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    int tail_length    = 64 - (length % 64);
    int round_length   = length + tail_length;
    uint8_t *input_end = input  + length;

    bzero(input_end,tail_length);

    *input_end = 1 << 7;
    ((unsigned*)input)[(round_length - 4)/4] = bswap_32(length*8);

    for (int i = 0; i < round_length; i += 64) {
        le_bswap_array(&input[i],16);
        sha1_block (&input[i],h);
        le_bswap_array(&input[i],16);
    }

    for (int i = 0; i < 5; i++)
        buffer[i] = bswap_32(h[i]);
}
