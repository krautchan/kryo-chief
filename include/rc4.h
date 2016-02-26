#ifndef RC4_H_
#define RC4_H_

#include <stdint.h>

typedef struct rc4_ctx_t {
	uint8_t idx1, idx2;
	uint8_t table[256];
} rc4_ctx_t;

#define rc4_drop(ctx, n) rc4_gen((ctx), NULL, (n))

void rc4_init(rc4_ctx_t *ctx, const uint8_t *key, const size_t len);
void rc4_gen(rc4_ctx_t *ctx, uint8_t *stream, const size_t len);

#endif
