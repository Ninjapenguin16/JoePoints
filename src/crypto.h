#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int pbkdf2_hmac_sha256(const uint8_t *pass, size_t passlen, const uint8_t *salt,
                       size_t saltlen, uint32_t iterations, uint8_t *out,
                       size_t outlen);

void hex_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen);
int hex_decode(const char *hex, uint8_t *out, size_t outlen);
int generate_salt_bytes(uint8_t *out, size_t salt_bytes);

#endif // CRYPTO_H
