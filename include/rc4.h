#ifndef RC4_H_
#define RC4_H_

#include <stdint.h>

typedef struct rc4_ctx_t {
	uint8_t idx1, idx2;
	uint8_t table[256];
} rc4_ctx_t;

#define rc4_drop(n, ctx) rc4_gen(NULL, (n), (ctx))

rc4_ctx_t rc4_init(const uint8_t *key, const size_t len);
void rc4_gen(uint8_t *stream, const size_t len, rc4_ctx_t *ctx);

#endif
