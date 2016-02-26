#include <stdint.h>
#include <stdlib.h>

#include "rc4.h"

void rc4_init(rc4_ctx_t *ctx, const uint8_t *key, const size_t len) {
	size_t i;
	uint8_t j, temp;

	for(i = 0; i < 256; i++)
		ctx->table[i] = i;

	j = 0;

	for(i = 0; i < 256; i++) {
		j += ctx->table[i] + key[i % len];
		
		temp = ctx->table[i];
		ctx->table[i] = ctx->table[j];
		ctx->table[j] = temp;
	}

	ctx->idx1 = ctx->idx2 = 0;
}

void rc4_gen(rc4_ctx_t *ctx, uint8_t *stream, const size_t len) {
	size_t n;
	uint8_t temp, idx1, idx2;

	for(n = 0; n < len; n++) {
		ctx->idx1++;
		ctx->idx2 += ctx->table[ctx->idx1];

		idx1 = ctx->idx1;
		idx2 = ctx->idx2;

		temp = ctx->table[idx1];
		ctx->table[idx1] = ctx->table[idx2];
		ctx->table[idx2] = temp;

		if(stream) {
			idx1 = ctx->table[ctx->idx1];
			idx2 = ctx->table[ctx->idx2];

			stream[n] = ctx->table[(idx1 + idx2) & 255];
		}
	}
}
