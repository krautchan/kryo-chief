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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "etc.h"
#include "rc4.h"
#include "sha256.h"

/* sha256("") */
static const uint8_t lhash[SHA256_SIZE] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

uint8_t *oaep(const uint8_t *msg, const size_t msglen, const size_t ksize_bytes) {
	uint8_t seed[SHA256_SIZE], *DB, *mask, *out = NULL;
	uint8_t sha256_out[SHA256_SIZE];
	rc4_ctx_t rc4_ctx;
	size_t padlen, dblen;

	if(msglen + 2 * SHA256_SIZE + 2 > ksize_bytes) return NULL;

	dblen = ksize_bytes - SHA256_SIZE - 1;
	padlen = dblen - msglen - SHA256_SIZE;

	if((DB = malloc(dblen)) == NULL) return NULL;

	memcpy(DB, lhash, SHA256_SIZE);
	memcpy(DB + SHA256_SIZE + padlen, msg, msglen);
	memset(DB + SHA256_SIZE, 0, padlen - 1);
	DB[SHA256_SIZE + padlen - 1] = 1;

	if((mask = malloc(dblen)) == NULL) goto freedb;

	getrand(seed, SHA256_SIZE, NULL);
	rc4_init(&rc4_ctx, seed, SHA256_SIZE);
	rc4_drop(&rc4_ctx, CONFIG_RC4_DROP);
	rc4_gen(&rc4_ctx, mask, dblen);
	xorblock(mask, DB, dblen);

	sha256(mask, dblen, sha256_out);
	xorblock(seed, sha256_out, SHA256_SIZE);

	if((out = malloc(ksize_bytes)) == NULL) goto freemask;

	out[0] = 0;
	memcpy(out + 1, seed, SHA256_SIZE);
	memcpy(out + SHA256_SIZE + 1, mask, dblen);

freemask:
	free(mask);
freedb:
	free(DB);

	return out;
}

uint8_t *inv_oaep(const uint8_t *in, const size_t inlen, const size_t ksize_bytes, size_t *msglen) {
	uint8_t *DB, seed[SHA256_SIZE], *mask, *out = NULL;
	uint8_t sha256_out[SHA256_SIZE];
	size_t dblen, outlen;
	rc4_ctx_t rc4_ctx;

	if(inlen < SHA256_SIZE * 2 + 1) return NULL;
	if(inlen > ksize_bytes) return NULL;

	memcpy(seed, in + 1, SHA256_SIZE);
	dblen = ksize_bytes - SHA256_SIZE - 1;
	if((DB = malloc(dblen)) == NULL) return NULL;
	memcpy(DB, in + SHA256_SIZE + 1, dblen);

	sha256(DB, dblen, sha256_out);
	xorblock(seed, sha256_out, SHA256_SIZE);
	
	if((mask = malloc(dblen)) == NULL) goto freedb;
	rc4_init(&rc4_ctx, seed, SHA256_SIZE);
	rc4_drop(&rc4_ctx, CONFIG_RC4_DROP);
	rc4_gen(&rc4_ctx, mask, dblen);
	xorblock(DB, mask, dblen);
	free(mask);

	if(memcmp(DB, lhash, SHA256_SIZE)) goto freedb;

	outlen = SHA256_SIZE;
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
