/**
 * @brief Cryptographic random number generator
 * 
 * @file random.h
 * @author Max Resch <resch.max@gmail.com>
 */

#ifndef N2N_RANDOM_H_
#define N2N_RANDOM_H_

#if defined(_WIN32) && !defined(USE_BCRYPT)
#define USE_BCRYPT 1
#endif

#include <stddef.h>
#include <stdint.h>

#if USE_OPENSSL
#include <openssl/rand.h>
#elif USE_NETTLE
#include <nettle/yarrow.h>
#elif USE_GCRYPT
#include <gcrypt.h>
#elif USE_MBEDTLS
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#elif USE_ELL
#include <ell/random.h>
#elif USE_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#endif

typedef struct random_ctx {
#if USE_NETTLE
    struct yarrow256_ctx     random;
#elif USE_MBEDTLS
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context random;
#elif USE_BCRYPT
    BCRYPT_ALG_HANDLE        hRandom;
#else
    int                      fd;
#endif
} *random_ctx_t;

void random_init(random_ctx_t ctx);

void random_free(random_ctx_t ctx);

void random_bytes(random_ctx_t ctx, uint8_t* buffer, size_t size);

#endif // N2N_RANDOM_H_