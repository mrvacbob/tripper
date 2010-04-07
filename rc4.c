static inline void rc4(const unsigned char * input, unsigned char * output, unsigned int ilen)
{
	unsigned char S[256];
	unsigned short i=0;
	unsigned char swaptemp=0,j=0,i2=0,i3=0;
	for (;i<=255; i++) {S[i]=i;}
	for (i=0;i<=255; i++) { 
        j = (j + S[i] + input[i2++]);
        swaptemp = S[i]; S[i] = S[j]; S[j] = swaptemp;
		if (i2 == ilen) i2 = 0;
    }
    i=i2=i3=j=0;
	for (;i<=255;i++) {
		j += S[++i2];
        swaptemp = S[i2]; S[i2] = S[j]; S[j] = swaptemp;
    }
    for (; i3 < 6; i3++) {
        j += S[++i2]; 
        output[i3] = S[(unsigned char)(S[i2] + S[j])]; 
        swaptemp = S[i2]; S[i2] = S[j]; S[j] = swaptemp;
    }
}
