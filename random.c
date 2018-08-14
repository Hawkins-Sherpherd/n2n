#include "random.h"

#include <stdint.h>
#include <stdlib.h>

#if __unix__
#include <unistd.h>
#include <fcntl.h>
#endif

void random_init(random_ctx_t ctx) {
#if USE_OPENSSL | USE_GCRYPT
#elif USE_ELL
    if (!l_getrandom_is_supported())
        ctx->fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    else
        ctx->fd = -1;
#elif USE_NETTLE
    yarrow256_init(&ctx->random, 0, NULL);
    uint8_t rnd_data[YARROW256_SEED_FILE_SIZE];
    int fd = open("/dev/random", O_RDONLY);
    read(fd, rnd_data, sizeof(rnd_data));
    close(fd);
    yarrow256_seed(&ctx->random, YARROW256_SEED_FILE_SIZE, rnd_data);
#elif USE_MBEDTLS
    mbedtls_ctr_drbg_init(&ctx->random);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_entropy_add_source(&ctx->entropy, &mbedtls_platform_entropy_poll, NULL, 16, MBEDTLS_ENTROPY_SOURCE_STRONG);
    mbedtls_ctr_drbg_seed(&ctx->random, &mbedtls_entropy_func, &ctx->entropy, NULL, 0);
#elif USE_BCRYPT
    BCryptOpenAlgorithmProvider (&ctx->hRandom, BCRYPT_RNG_ALGORITHM, NULL, 0);
#elif __unix__
    ctx->fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
#endif
}

void random_free(random_ctx_t ctx) {
#if USE_OPENSSL | USE_GCRYPT | USE_NETTLE
#elif USE_ELL
    if (ctx->fd != -1)
        close(ctx->fd);
#elif USE_MBEDTLS
    mbedtls_ctr_drbg_free(&ctx->random);
    mbedtls_entropy_free(&ctx->entropy);
#elif USE_BCRYPT
    BCryptCloseAlgorithmProvider( ctx->hRandom, 0 );
#elif __unix__
    close(ctx->fd);
#endif
}

void random_bytes(random_ctx_t ctx, uint8_t* buffer, size_t size) {
#if USE_OPENSSL
    RAND_bytes((void*) buffer, size);
#elif USE_NETTLE
    yarrow256_random(&ctx->random, size, buffer);
#elif USE_GCRYPT
    gcry_create_nonce(buffer, size);
#elif USE_MBEDTLS
    mbedtls_ctr_drbg_random(&ctx->random, buffer, (uint32_t) size);
#elif USE_ELL
    if (ctx->fd == -1)
        l_getrandom(buffer, (uint32_t) size);
    else
        read(ctx->fd, buffer, size);
#elif USE_BCRYPT
    BCryptGenRandom(ctx->hRandom, buffer, (uint32_t) size, 0);
#else
    read(ctx->fd, buffer, size);
#endif
}
