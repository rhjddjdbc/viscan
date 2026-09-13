#include "hash_utils.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

int compute_md5(const char *filename, char *output) {
    if (!filename || !output) return -1;

    FILE *file = fopen(filename, "rb");
    if (!file) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(file); return -1; }

    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
        EVP_DigestUpdate(ctx, buf, n);
    }

    if (ferror(file)) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -1;
    }
    fclose(file);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0';
    return 0;
}
