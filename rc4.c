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
