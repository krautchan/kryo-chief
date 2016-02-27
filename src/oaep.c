#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etc.h"
#include "rc4.h"
#include "sha256.h"

/* sha256("") */
static const uint8_t lhash[32] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

uint8_t *oaep(const uint8_t *msg, const size_t msglen, const size_t modlen) {
	uint8_t seed[32], *DB, *mask, *out = NULL;
	uint8_t sha256_out[32];
	rc4_ctx_t rc4_ctx;
	size_t padlen, dblen;

	dblen = modlen / 8 - 33; /* 0x00 + seed[32] */
	padlen = dblen - msglen - 32; /* lhash[32] */

	if(dblen < msglen + 32) return NULL;
	if((DB = malloc(dblen)) == NULL) return NULL;

	memcpy(DB, lhash, 32);
	memcpy(DB + 32 + padlen, msg, msglen);
	memset(DB + 32, 0, padlen - 1);
	DB[32 + padlen - 1] = 1;

	if((mask = malloc(dblen)) == NULL) goto freedb;

	getrand(seed, 32, NULL);
	rc4_init(&rc4_ctx, seed, 32);
	rc4_drop(&rc4_ctx, 4096);
	rc4_gen(&rc4_ctx, mask, dblen);
	xorblock(mask, DB, dblen);

	sha256(mask, dblen, sha256_out);
	xorblock(seed, sha256_out, 32);

	if((out = malloc(modlen / 8)) == NULL) goto freemask;

	out[0] = 0;
	memcpy(out + 1, seed, 32);
	memcpy(out + 33, mask, dblen);

freemask:
	free(mask);
freedb:
	free(DB);

	return out;
}

uint8_t *inv_oaep(const uint8_t *in, const size_t modlen, size_t *msglen) {
	uint8_t *DB, seed[32], *mask, *out = NULL;
	uint8_t sha256_out[32];
	size_t dblen, outlen;
	rc4_ctx_t rc4_ctx;

	memcpy(seed, in + 1, 32);

	if(modlen / 8 < 33) return NULL;
	dblen = modlen / 8 - 33;
	if((DB = malloc(dblen)) == NULL) return NULL;
	memcpy(DB, in + 33, dblen);

	sha256(DB, dblen, sha256_out);
	xorblock(seed, sha256_out, 32);
	
	if((mask = malloc(dblen)) == NULL) goto freedb;
	rc4_init(&rc4_ctx, seed, 32);
	rc4_drop(&rc4_ctx, 4096);
	rc4_gen(&rc4_ctx, mask, dblen);
	xorblock(DB, mask, dblen);
	free(mask);

	if(memcmp(DB, lhash, 32)) goto freedb;

	outlen = 32;
	while(!DB[outlen++]);
	outlen = dblen - outlen;

	if(outlen > 0) {
		if((out = malloc(outlen)) == NULL) goto freedb;
		memcpy(out, DB + dblen - outlen, outlen);
	} 

	if(msglen)
		*msglen = outlen;

freedb:
	free(DB);
	return out;
	
}
