#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define rotr(x, n) ((x >> n) | (x << (32 - n)))

typedef struct sha256_t {
	uint32_t h[8];
	uint8_t *string;
} sha256_t;

sha256_t sha256(const uint8_t *in, const int size);
void sha256_free(sha256_t h);

#endif 
