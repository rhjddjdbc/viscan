#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>

int compute_md5(const char *filename, char *output) {
    FILE *file = fopen(filename, "rb");
    if (!file) return -1;

    MD5_CTX ctx;
    MD5_Init(&ctx);

    unsigned char data[1024];
    int bytes;
    while ((bytes = fread(data, 1, 1024, file)) > 0) {
        MD5_Update(&ctx, data, bytes);
    }

    fclose(file);

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &ctx);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    output[32] = '\0';
    return 0;
}

