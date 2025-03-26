

#ifndef MYPROVIDER_H
#define MYPROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    EVP_CIPHER_CTX *cipher_ctx;
    unsigned char key[32];
    unsigned char iv[16];
} MYPROV_CIPHER_CTX;;

void *aes256_cbc_newctx(void *provctx);
void aes256_cbc_freectx(void *vctx);
int aes256cbc_encrypt_init(void *ctx, const unsigned char *key, const unsigned char *iv, size_t keylen, size_t ivlen, const OSSL_PARAM params[]);

int aes256_cbc_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                            const unsigned char *iv, size_t ivlen);
int aes256cbc_update(void *ctx, unsigned char *out, size_t *outl,
                       size_t outsize, const unsigned char *in, size_t inl);
int aes256cbc_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize);

extern const OSSL_DISPATCH aes256_cbc_functions[];
extern const OSSL_ALGORITHM aes256_cbc_algorithms[];
extern const OSSL_DISPATCH aes_provider_functions[];

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx);
#endif //MYPROVIDER_H
