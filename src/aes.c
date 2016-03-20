/* 
 * HTR -- The Heisetrolljan
 * 
 * Copyright (C) 2016  Martin Wolters
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to 
 * the Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA
 * 
 */

#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "aes_tables.h"

static void sub_bytes(uint8_t *state) {
	uint32_t i;
	for(i = 0; i < NB * 4; i++)
		state[i] = s[state[i]];
}

static void inv_sub_bytes(uint8_t *state) {
	uint32_t i;
	for(i = 0; i < NB * 4; i++)
		state[i] = inv_s[state[i]];
}

static void shift_rows(uint8_t *state) {
	uint8_t temp;

	temp              = state[1 * NB + 0];
	state[1 * NB + 0] = state[1 * NB + 1];
	state[1 * NB + 1] = state[1 * NB + 2];
	state[1 * NB + 2] = state[1 * NB + 3];
	state[1 * NB + 3] = temp;

	temp              = state[2 * NB + 0];
	state[2 * NB + 0] = state[2 * NB + 2];
	state[2 * NB + 2] = temp;
	temp              = state[2 * NB + 1];
	state[2 * NB + 1] = state[2 * NB + 3];
	state[2 * NB + 3] = temp;

	temp              = state[3 * NB + 3];
	state[3 * NB + 3] = state[3 * NB + 2];
	state[3 * NB + 2] = state[3 * NB + 1];
	state[3 * NB + 1] = state[3 * NB + 0];
	state[3 * NB + 0] = temp;
}

static void inv_shift_rows(uint8_t *state) {
	uint8_t temp;

	temp              = state[1 * NB + 3];
	state[1 * NB + 3] = state[1 * NB + 2];
	state[1 * NB + 2] = state[1 * NB + 1];
	state[1 * NB + 1] = state[1 * NB + 0];
	state[1 * NB + 0] = temp;

	temp              = state[2 * NB + 0];
	state[2 * NB + 0] = state[2 * NB + 2];
	state[2 * NB + 2] = temp;
	temp              = state[2 * NB + 1];
	state[2 * NB + 1] = state[2 * NB + 3];
	state[2 * NB + 3] = temp;

	temp              = state[3 * NB + 0];
	state[3 * NB + 0] = state[3 * NB + 1];
	state[3 * NB + 1] = state[3 * NB + 2];
	state[3 * NB + 2] = state[3 * NB + 3];
	state[3 * NB + 3] = temp;
}

/* 
 * The following functions are taken from 
 * http://www.codeplanet.eu/tutorials/cpp/51-advanced-encryption-standard.html
 */

static uint8_t mul_gf(uint8_t a, uint8_t b) {
	uint8_t out = 0, hi, i;

	for(i = 0; i < 8; i++) {
		if(b & 1)
			out ^= a;
		hi = a & 0x80;
		a <<= 1;
		if(hi)
			a ^= 0x1b;
		b >>= 1;
	}

	return out;
}

static void mix_column(uint8_t *column) {
	uint8_t cpy[4];

	memcpy(cpy, column, 4);

	column[0] = mul_gf(cpy[0], 2) ^
				mul_gf(cpy[1], 3) ^
				mul_gf(cpy[2], 1) ^
				mul_gf(cpy[3], 1);

	column[1] = mul_gf(cpy[0], 1) ^
				mul_gf(cpy[1], 2) ^
				mul_gf(cpy[2], 3) ^
				mul_gf(cpy[3], 1);

	column[2] = mul_gf(cpy[0], 1) ^
				mul_gf(cpy[1], 1) ^
				mul_gf(cpy[2], 2) ^
				mul_gf(cpy[3], 3);

	column[3] = mul_gf(cpy[0], 3) ^
				mul_gf(cpy[1], 1) ^
				mul_gf(cpy[2], 1) ^
				mul_gf(cpy[3], 2);
}

static void inv_mix_column(uint8_t *column) {
	uint8_t cpy[4];

	memcpy(cpy, column, 4);

	column[0] = mul_gf(cpy[0], 0xe) ^
				mul_gf(cpy[1], 0xb) ^
				mul_gf(cpy[2], 0xd) ^
				mul_gf(cpy[3], 0x9);

	column[1] = mul_gf(cpy[0], 0x9) ^
				mul_gf(cpy[1], 0xe) ^
				mul_gf(cpy[2], 0xb) ^
				mul_gf(cpy[3], 0xd);

	column[2] = mul_gf(cpy[0], 0xd) ^
				mul_gf(cpy[1], 0x9) ^
				mul_gf(cpy[2], 0xe) ^
				mul_gf(cpy[3], 0xb);

	column[3] = mul_gf(cpy[0], 0xb) ^
				mul_gf(cpy[1], 0xd) ^
				mul_gf(cpy[2], 0x9) ^
				mul_gf(cpy[3], 0xe);
}

static void mix_columns(uint8_t *state, int mode) {
	int i, j;
	uint8_t column[4];

	for(i = 0; i < NB; i++) {
		for(j = 0; j < 4; j++)
			column[j] = state[4 * j + i];

		if(mode == FOR_MIX)
			mix_column(column);
		else
			inv_mix_column(column);

		for(j = 0; j < 4; j++)
			state[4 * j + i] = column[j];
	}
}

static void add_roundkey(uint8_t *state, uint32_t *expkey, int round) {
	int i;

	for(i = 0; i < NB; i++) {
		state[0 * NB + i] ^= ((expkey[round * NB + i] >> 24) & 255);
		state[1 * NB + i] ^= ((expkey[round * NB + i] >> 16) & 255);
		state[2 * NB + i] ^= ((expkey[round * NB + i] >>  8) & 255);
		state[3 * NB + i] ^= ((expkey[round * NB + i]      ) & 255);
	}
}

static void *key_expansion(uint32_t *key, uint32_t *w) {
	int i;
	uint32_t temp;

	for(i = 0; i < NK; i++)
		w[i] = key[i];

	for(i = NK; i < NB * (NR + 1); i++) {
		temp = w[i - 1];
		if(i % NK == 0) {
			temp = sub_byte(rot_byte(temp)) ^ (rcon[i / NK] << 24);
		}
#if NK > 6
		else if(i % NK == 4)
			temp = sub_byte(temp);
#endif
		w[i] = w[i - NK] ^ temp;
	}

	return w;
}

static void tostate(const uint8_t *data, uint8_t *state) {
    int i;

    for(i = 0; i < 4; i++) {
        state[0 * NB + i] = data[i * NB + 0];
        state[1 * NB + i] = data[i * NB + 1];
        state[2 * NB + i] = data[i * NB + 2];
        state[3 * NB + i] = data[i * NB + 3];
    }
}

void aes_enc(aes_ctx_t *ctx) {
	int i;

	add_roundkey(ctx->state, ctx->expkey, 0);
	for(i = 1; i < NR; i++) {
		sub_bytes(ctx->state);
		shift_rows(ctx->state);
		mix_columns(ctx->state, FOR_MIX);
		add_roundkey(ctx->state, ctx->expkey, i);
	}
	sub_bytes(ctx->state);
	shift_rows(ctx->state);
	add_roundkey(ctx->state, ctx->expkey, NR);
}

void aes_dec(aes_ctx_t *ctx) {
	int i;
	uint32_t *expkey = ctx->expkey;
	uint8_t *state = ctx->state;

	add_roundkey(state, expkey, NR);
	inv_shift_rows(state);
	inv_sub_bytes(state);
	for(i = NR - 1; i > 0; i--) {
		add_roundkey(state, expkey, i);
		mix_columns(state, INV_MIX);
		inv_shift_rows(state);
		inv_sub_bytes(state);
	}
	add_roundkey(state, expkey, 0);
}

void aes_update(aes_ctx_t *ctx, const uint8_t *data, const uint8_t *key) {
	uint32_t intkey[NK];
	int i;

	if(key) {
		free(ctx->expkey);
		for(i = 0; i < NK; i++)
			intkey[i] = key[i * 4    ] << 24 |
						key[i * 4 + 1] << 16 |
						key[i * 4 + 2] <<  8 |
						key[i * 4 + 3];
		key_expansion(intkey, ctx->expkey);
	}	
	
	if(data)
		tostate(data, ctx->state);
}

void aes_init(aes_ctx_t *ctx, const uint8_t *data, const uint8_t *key) {
	uint32_t intkey[NK];
	int i;
	
	for(i = 0; i < NK; i++)
		intkey[i] = key[i * 4    ] << 24 |
					key[i * 4 + 1] << 16 |
					key[i * 4 + 2] <<  8 |
					key[i * 4 + 3];
	key_expansion(intkey, ctx->expkey);

	if(data)
		tostate(data, ctx->state);
	else
		memset(ctx->state, 0, AES_BSIZE);
}

void aes_tostr(aes_ctx_t ctx, uint8_t *out) {
	size_t i;

	for(i = 0; i < NB; i++) {
		out[i * 4 + 0] = ctx.state[0 * NB + i];
		out[i * 4 + 1] = ctx.state[1 * NB + i];
		out[i * 4 + 2] = ctx.state[2 * NB + i];
		out[i * 4 + 3] = ctx.state[3 * NB + i];
	}
}
