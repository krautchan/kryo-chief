#include <stdint.h>
#include <stdlib.h>

#include "rc4.h"

rc4_ctx_t rc4_init(const uint8_t *key, const size_t len) {
	size_t i;
	uint8_t j, temp;
	rc4_ctx_t out;

	for(i = 0; i < 256; i++)
		out.table[i] = i;

	j = 0;

	for(i = 0; i < 256; i++) {
		j += out.table[i] + key[i % len];
		
		temp = out.table[i];
		out.table[i] = out.table[j];
		out.table[j] = temp;
	}

	out.idx1 = out.idx2 = 0;
	return out;
}

void rc4_gen(uint8_t *stream, const size_t len, rc4_ctx_t *ctx) {
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
