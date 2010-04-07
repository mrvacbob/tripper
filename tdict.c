/* Brute-force tripcode finder, for 2channel boards.
 * Will work with restrictions on Wakaba/Wakaba-ZERO/Kareha/Shiichan/Futallaby/Futaba/Etc.
 * Tripcode output containing <>"'!#,& may not work.
 *
 * Use: build.sh
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
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>

#include "crypt.c"

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

static char *
tripcode_2ch(const unsigned char *input, unsigned int ilen)
{
    char            salt[2];

    if (ilen >= 2) {
        salt[0] = tripsaltclean(input[1]);
        salt[1] = (ilen > 2)? tripsaltclean(input[2]):'H';
    } else {salt[0] = 'H'; salt[1] = '.';}

    return crypt((char*)input, salt) + 3;
}
static unsigned char tripcode_inputs[95] = " \"$%&'()*+,-.!/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

static unsigned int htmlspecialchars(const unsigned char *tripindexes, unsigned char *htmled, unsigned char ilen)
{
    unsigned char i=0,i2=0;
    for (;i < ilen; i++) {
        unsigned char c = tripindexes[i];
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

int
main(int argc, const char *argv[])
{
	FILE *dict = fopen(argv[1],"r");
	size_t qq;
	char *istr;
	char ih[64],*trip;
	init_des();
	while (istr = fgetln(dict,&qq)) {
	 qq--;
	 int l = htmlspecialchars(istr,ih,qq);
	 ih[l] = 0;
     trip = tripcode_2ch(ih, l);
	 fwrite(istr,1,qq,stdout);
	 printf(" !%s\n",trip);
	}
    return 0;
}
