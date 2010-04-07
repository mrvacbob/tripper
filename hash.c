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

#include <stdlib.h>
#include <string.h>

static const unsigned char b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline void base64(const unsigned char *hash, unsigned char *buffer, int length)
{
    int i=0;
    
    for (; i < (length/3); i++) {
        int i3 = i*3, i4 = i*4;
        unsigned bits = hash[i3]<<16 | hash[i3+1]<<8 | hash[i3+2];
        
        buffer[i4+0] = b64[(bits>>18) % 64];
        buffer[i4+1] = b64[(bits>>12) % 64];
        buffer[i4+2] = b64[(bits>>6) % 64];
        buffer[i4+3] = b64[bits % 64];
    }
}

static inline void swap(unsigned char *a, unsigned char *b)
{
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}

static void rc4(const unsigned char * input, unsigned char * output, unsigned int ilen)
{
	unsigned char S[256];
	unsigned short i=0;
	unsigned char j=0,i2=0,i3;
	for (;i<=255; i++) {S[i]=i;}
	for (i=0;i<=255; i++) { 
        j = (j + S[i] + input[i2++]);
        swap(&S[i], &S[j]);
		if (i2 == ilen) i2 = 0;
    }
    i=i2=i3=j=0;
	for (;i<=255;i++) {
		j += S[++i2];
        swap(&S[i2], &S[j]);
    }
    for (; i3 < 6; i3++) {
        j += S[++i2]; 
        output[i3] = S[(S[i2] + S[j])%256]; 
        swap(&S[i2], &S[j]);
    }
}

#define lr(a,b) (((a)<<b)|(((a))>>(32-b)))
static void SHA1_one(unsigned char *input, unsigned int *h0, unsigned int *h1, unsigned int *h2, unsigned int *h3, unsigned int *h4)
{
    unsigned int a,b,c,d,e,i;
    unsigned int *blockTmp = (unsigned int*)input;

    a = *h0;
    b = *h1;
    c = *h2;
    d = *h3;
    e = *h4;

    for (i = 0; i < 80; i++) {
        unsigned int temp = lr(a,5) + e, f, temp2;
        if (i < 16) temp += blockTmp[i]; else {temp2 = blockTmp[(i-3)%16] ^ blockTmp[(i-8)%16] ^ blockTmp[(i-14)%16] ^ blockTmp[i%16]; blockTmp[i%16] = temp2 = lr(temp2,1); temp += temp2;}
        if (i < 20) {f = d^(b&(c^d)); temp2 = 0x5A827999;}
        else if (i < 40) {f = b^c^d; temp2 = 0x6ED9EBA1;}
        else if (i < 60) {f = (b&c)|(b&d)|(c&d); temp2 = 0x8F1BBCDC;} // f = (b&c)|(b&d)|(c&d);
        else {f = b^c^d; temp2 = 0xCA62C1D6;}
        e = d; d = c; c = lr(b,30); b = a; a = temp+f+temp2;
    }

    *h0 += a;
    *h1 += b;
    *h2 += c;
    *h3 += d;
    *h4 += e;
}

static void array_swap(unsigned char *a_, unsigned int size)
{
	unsigned int *a = (unsigned int *)a_;
	if (htonl(1) == 1) return;
	while (size--) {*a = htonl(*a); a++;}
}

// It's assumed that input is allocated a multiple of 64 bytes and we can overwrite it
static void sha1(unsigned char *input, unsigned int ilen, unsigned int *buffer)
{
    unsigned char *inputend = &input[ilen];
	unsigned int ilenrnd = 64-(ilen%64);
	unsigned int h0,h1,h2,h3,h4,blocki,shats = ilen + ilenrnd;
    bzero(inputend,ilenrnd);
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;
    *inputend = 1<<7;
	((unsigned int*)input)[(shats - 4)/4] = htonl(ilen*8);
    for (blocki = 0; blocki < shats; blocki += 64) {array_swap(&input[blocki],16); SHA1_one(&input[blocki],&h0,&h1,&h2,&h3,&h4); array_swap(&input[blocki],16);}
	buffer[0] = htonl(h0); buffer[1] = htonl(h1); buffer[2] = htonl(h2); buffer[3] = htonl(h3); buffer[4] = htonl(h4);
}
