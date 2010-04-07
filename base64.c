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
