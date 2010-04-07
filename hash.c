/*
 Copyright (c) 2004-2010 Alexander Strange <astrange@ithinksw.com>

 Permission to use, copy, modify, and/or distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
 
 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

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

/*
 *  sha1.c
 *
 *  Created by Alexander Strange on 10/23/04.
 *  WTFPL goes here
 */

#include <stdlib.h>
#include <string.h>

/*
 Initialize variables:
 a = h0 = 0x67452301
 b = h1 = 0xEFCDAB89
 c = h2 = 0x98BADCFE
 d = h3 = 0x10325476
 e = h4 = 0xC3D2E1F0
 
 Pre-processing:
 append 1 to message
 append 0 until message length == 448 (mod 512)
 append length of message as 64-bit integer to message
 
 Process the message in successive 512-bit chunks:
 break message into 512-bit chunks
 for each chunk:
 break chunk into sixteen 32-bit words w(i), 0 ≤ i ≤ 15
 
 Extend the sixteen 32-bit words into eighty 32-bit words:
 for i from 16 to 79:
 w(i) = (w(i-3) xor w(i-8) xor w(i-14) xor w(i-16)) leftrotate 1
 
 Main loop:
 for i from 0 to 79:
 temp = (a leftrotate 5) + f(b,c,d) + e + k + w(i)   note: all addition is mod 232
 where:
 (0  ≤ i ≤ 19): f(b,c,d) = (b and c) or ((not b) and d),         k = 0x5A827999
 (20 ≤ i ≤ 39): f(b,c,d) = (b xor c xor d),                      k = 0x6ED9EBA1
 (40 ≤ i ≤ 59): f(b,c,d) = (b and c) or (b and d) or (c and d),  k = 0x8F1BBCDC
 (60 ≤ i ≤ 79): f(b,c,d) = (b xor c xor d),                      k = 0xCA62C1D6
 e = d
 d = c
 c = b leftrotate 30
 b = a
 a = temp
 
 h0 = h0 + a
 h1 = h1 + b 
 h2 = h2 + c
 h3 = h3 + d
 h4 = h4 + e
 
 digest = hash = h0 append h1 append h2 append h3 append h4
 
 Note: Instead of the formulation from FIPS PUB 180-1 shown, the following may be used for improved efficiency:
 
 (0 <= i <= 19): f(b,c,d) = (d xor (b and (c xor d)))
 (40 <= i <= 59): f(b,c,d) = (b and c) or (d and (b or c)))
 
 */

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
        else if (i < 60) {f = (b&c)|(d&(b|c)); temp2 = 0x8F1BBCDC;}
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

/* It's assumed that input is allocated a multiple of 64 bytes and we can overwrite it */
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
//    ((unsigned long long*)input)[(ilen+(56-(ilen%64)))/8] = ilen*8;
	((unsigned int*)input)[(shats - 4)/4] = htonl(ilen*8);
	// the above is "append length of message (before pre-processing), in bits as 64-bit big-endian integer to message"
    for (blocki = 0; blocki < shats; blocki += 64) {array_swap(&input[blocki],16); SHA1_one(&input[blocki],&h0,&h1,&h2,&h3,&h4); array_swap(&input[blocki],16);}
	buffer[0] = htonl(h0); buffer[1] = htonl(h1); buffer[2] = htonl(h2); buffer[3] = htonl(h3); buffer[4] = htonl(h4);
}
