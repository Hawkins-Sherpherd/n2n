/**
 * @brief AES crypto library abstraction layer
 * 
 * @file aes.h
 * @author Max Resch <resch.max@gmail.com>
 * @date 2018
 */

#ifndef N2N_AES_H_
#define N2N_AES_H_

#ifdef N2N_HAVE_AES

#include <stddef.h>
#include <stdint.h>


#if USE_OPENSSL
#include <string.h>
#include <openssl/evp.h>
#elif USE_NETTLE
#include <nettle/aes.h>
#include <nettle/cbc.h>
#elif USE_GCRYPT
#include <gcrypt.h>
#elif USE_MBEDTLS
#include <mbedtls/cipher.h>
#elif USE_ELL
#include <stdbool.h>
#include <ell/cipher.h>
#elif USE_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#else
#error "Unknown Crypto Library"
#endif

#define AES256_KEY_BYTES (256/8)
#define AES192_KEY_BYTES (192/8)
#define AES128_KEY_BYTES (128/8)

#define AES_BLOCK_SIZE 16

typedef struct cipher_ctx {
#if USE_OPENSSL
    EVP_CIPHER_CTX      *ctx;
    const EVP_CIPHER    *cipher;
    uint8_t             key[AES256_KEY_BYTES];
#elif USE_NETTLE
    struct aes256_ctx   enc_ctx;
    struct aes256_ctx   dec_ctx;
    nettle_cipher_func* enc_fun;
    nettle_cipher_func* dec_fun;
#elif USE_GCRYPT
    gcry_cipher_hd_t    cipher;
#elif USE_MBEDTLS
    mbedtls_cipher_context_t enc_ctx;
    mbedtls_cipher_context_t dec_ctx;
#elif USE_ELL
    struct l_cipher* cipher;
#elif USE_BCRYPT
    BCRYPT_ALG_HANDLE   hAlgorithm;
    BCRYPT_KEY_HANDLE   hKey;
#endif
} *cipher_ctx_t;

void n2n_aes_init(cipher_ctx_t ctx);

void n2n_aes_free(cipher_ctx_t ctx);

uint8_t n2n_aes_set_key(cipher_ctx_t ctx, const uint8_t* key, size_t length);

void n2n_aes_encrypt(cipher_ctx_t ctx, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t length);

void n2n_aes_decrypt(cipher_ctx_t ctx, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t length);

#endif // N2N_HAVE_AES
#endif // N2N_AES_H_
