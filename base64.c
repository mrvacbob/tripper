#ifdef SHIICHAN4K
static inline void b64sha(const unsigned char *hash,unsigned char *buffer)
{
    static const unsigned char b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned long bits = hash[0]<<16|hash[1]<<8|hash[2];
    buffer[0] = b64[(bits>>18) % 64];
    buffer[1] = b64[(bits>>12) % 64];
    buffer[2] = b64[(bits>>6) % 64];
    buffer[3] = b64[bits % 64];
    bits = hash[3]<<16|hash[4]<<8|hash[5];
    buffer[4] = b64[(bits>>18) % 64];
    buffer[5] = b64[(bits>>12) % 64];
    buffer[6] = b64[(bits>>6) % 64];
    buffer[7] = b64[bits % 64];
    bits = hash[6]<<16|hash[7]<<8|hash[8];
    buffer[8] = b64[(bits>>18) % 64];
    buffer[9] = b64[(bits>>12) % 64];
    buffer[10] = b64[(bits>>6) % 64];
	buffer[11] = b64[bits % 64];
}
#else
#ifdef WAKABARC4
static inline void b64rc4(const unsigned char *hash, unsigned char *buffer)
{
	static const unsigned char b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned long bits = hash[0]<<16|hash[1]<<8|hash[2];
    buffer[0] = b64[(bits>>18) % 64];
    buffer[1] = b64[(bits>>12) % 64];
    buffer[2] = b64[(bits>>6) % 64];
    buffer[3] = b64[bits % 64];
    bits = hash[3]<<16|hash[4]<<8|hash[5];
    buffer[4] = b64[(bits>>18) % 64];
    buffer[5] = b64[(bits>>12) % 64];
    buffer[6] = b64[(bits>>6) % 64];
    buffer[7] = b64[bits % 64];
	bits = hash[6]<<16|hash[7]<<8|hash[8];
    buffer[8] = b64[(bits>>18) % 64];
    buffer[9] = b64[(bits>>12) % 64];
}
#endif
#endif
