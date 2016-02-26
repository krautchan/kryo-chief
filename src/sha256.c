/* From the description of SHA-256 in Wikipedia */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint8_t *statetochar(sha256_t in) {
	uint8_t *out = malloc(32);
	if(out == NULL) return NULL;
	
	out[0] = (in.h[0] >> 24) & 0xff;
	out[1] = (in.h[0] >> 16) & 0xff;
	out[2] = (in.h[0] >> 8) & 0xff;
	out[3] = in.h[0] & 0xff;
	out[4] = (in.h[1] >> 24) & 0xff;
	out[5] = (in.h[1] >> 16) & 0xff;
	out[6] = (in.h[1] >> 8) & 0xff;
	out[7] = in.h[1] & 0xff;
	out[8] = (in.h[2] >> 24) & 0xff;
	out[9] = (in.h[2] >> 16) & 0xff;
	out[10] = (in.h[2] >> 8) & 0xff;
	out[11] = in.h[2] & 0xff;
	out[12] = (in.h[3] >> 24) & 0xff;
	out[13] = (in.h[3] >> 16) & 0xff;
	out[14] = (in.h[3] >> 8) & 0xff;
	out[15] = in.h[3] & 0xff;
	out[16] = (in.h[4] >> 24) & 0xff;
	out[17] = (in.h[4] >> 16) & 0xff;
	out[18] = (in.h[4] >> 8) & 0xff;
	out[19] = in.h[4] & 0xff;
	out[20] = (in.h[5] >> 24) & 0xff;
	out[21] = (in.h[5] >> 16) & 0xff;
	out[22] = (in.h[5] >> 8) & 0xff;
	out[23] = in.h[5] & 0xff;
	out[24] = (in.h[6] >> 24) & 0xff;
	out[25] = (in.h[6] >> 16) & 0xff;
	out[26] = (in.h[6] >> 8) & 0xff;
	out[27] = in.h[6] & 0xff;
	out[28] = (in.h[7] >> 24) & 0xff;
	out[29] = (in.h[7] >> 16) & 0xff;
	out[30] = (in.h[7] >> 8) & 0xff;
	out[31] = in.h[7] & 0xff;

	return out;
}

static sha256_t sha256init(void) {
	sha256_t out;

	out.h[0] = 0x6a09e667;
	out.h[1] = 0xbb67ae85;
	out.h[2] = 0x3c6ef372;
	out.h[3] = 0xa54ff53a;
	out.h[4] = 0x510e527f;
	out.h[5] = 0x9b05688c;
	out.h[6] = 0x1f83d9ab;
	out.h[7] = 0x5be0cd19;

	out.string = NULL;

	return out;
}

int newsize(int insize) {
	int size;

	size = insize + 1;
	size += (size % 64 > 56)? 64: 0;
	size += 64 - size % 64;

	return size;
}

static uint8_t *preprocess(const uint8_t *in, int insize, int size) {
	uint8_t *out;
	int i;

	if((out = malloc(size)) == NULL)
		return NULL;

	memcpy(out, in, insize);
	out[insize] = 0x80;
	
	/* We assume size to be 32bit, so we
	   write the first 32 bits as zeroes. */

	for(i = insize + 1; i < size - 4; i++)
		out[i] = 0;
	for(i = 0; i < 4; i++)
		out[size - 4 + i] = ((insize * 8) >> ((3 - i) * 8)) & 0xff;

	return out;
}

static sha256_t digest(uint8_t *in, int size) {
	sha256_t state;
	int i, j, k;
	uint a, b, c, d, e, f, g, h;
	uint W[64], s0, s1, maj, t1, t2, ch;

	state = sha256init();

	for(i = 0; i < size / 64; i++) {
		for(j = 0; j < 16; j++) {
			W[j] = 0;
			for(k = 0; k < 4; k++) {
				W[j] <<= 8;
				W[j] |= in[i * 64 + j * 4 + k];
			}
		}

		for(j = 16; j < 64; j++) {
			s0 = rotr(W[j - 15], 7) ^ rotr(W[j - 15], 18) ^ (W[j - 15] >> 3);
			s1 = rotr(W[j - 2], 17) ^ rotr(W[j - 2], 19) ^ (W[j - 2] >> 10);
			W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		a = state.h[0];
		b = state.h[1];
		c = state.h[2];
		d = state.h[3];
		e = state.h[4];
		f = state.h[5];
		g = state.h[6];
		h = state.h[7];

		for(j = 0; j < 64; j++) {
			s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			t2 = s0 + maj;
			s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			ch = (e & f) ^ ((~e) & g);
			t1 = h + s1 + ch + K[j] + W[j];
			
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		state.h[0] += a;
		state.h[1] += b;
		state.h[2] += c;
		state.h[3] += d;
		state.h[4] += e;
		state.h[5] += f;
		state.h[6] += g;
		state.h[7] += h;
	}

	state.string = statetochar(state);
	return state;
}

sha256_t sha256(const uint8_t *in, const int insize) {
	uint8_t *prep;
	sha256_t out;
	int size = newsize(insize);

	prep = preprocess(in, insize, size);
	out = digest(prep, size);
	free(prep);

	return out;
}

void sha256_free(sha256_t h) {
	free(h.string);
}
