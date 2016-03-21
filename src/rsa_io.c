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
#include <stdlib.h>
#include <string.h>

#include <tommath.h>

#include "aes.h"
#include "config.h"
#include "etc.h"
#include "etc_math.h"
#include "oaep.h"
#include "rsa.h"
#include "rsa_int.h"
#include "rsa_io.h"
#include "sha256.h"

static rsa_keypair_t *emptypublic(void) {
	rsa_keypair_t *out;
	
	if((out = malloc(sizeof(rsa_keypair_t))) == NULL) return NULL;
	if((out->modulus = malloc(sizeof(mp_int))) == NULL) goto freepair;
	if((out->public = malloc(sizeof(mp_int))) == NULL) goto freemod;

	out->secret = out->p = out->q = out->dp = out->dq = out->qi = NULL;
	return out;

freemod:
	free(out->modulus);
freepair:
	free(out);
	return NULL;
}

static rsa_keypair_t *emptypair(void) {
	rsa_keypair_t *out;
	
	if((out = malloc(sizeof(rsa_keypair_t))) == NULL) return NULL;
	if((out->modulus = malloc(sizeof(mp_int))) == NULL) goto freepair;
	if((out->public = malloc(sizeof(mp_int))) == NULL) goto freemod;
	if((out->secret = malloc(sizeof(mp_int))) == NULL) goto freepub;
	if((out->p = malloc(sizeof(mp_int))) == NULL) goto freesec;
	if((out->q = malloc(sizeof(mp_int))) == NULL) goto freep;
	if((out->dp = malloc(sizeof(mp_int))) == NULL) goto freeq;
	if((out->dq = malloc(sizeof(mp_int))) == NULL) goto freedp;
	if((out->qi = malloc(sizeof(mp_int))) == NULL) goto freedq;

	return out;

freedq:
	free(out->dq);
freedp:
	free(out->dp);
freeq:
	free(out->q);
freep:
	free(out->p);
freesec:
	free(out->secret);
freepub:
	free(out->public);
freemod:
	free(out->modulus);
freepair:
	free(out);
	return NULL;
}

static int checkdata(const uint8_t *data, const size_t len, const size_t n_numbers) {
	uint32_t readsize, sumsize = 0;
	size_t i, remaining = len;

	for(i = 0; i < n_numbers; i++) {
		if(remaining < INT_SIZE) return 0;
		readsize = *(data + sumsize);

		sumsize += INT_SIZE;
		remaining -= INT_SIZE;
		
		if(remaining < readsize) return 0;
		sumsize += readsize;
		remaining -= readsize;
	}
	return 1;
}

uint8_t *rsa_serialize_public(rsa_keypair_t *pair, size_t *len) {
	uint32_t bytes_m, bytes_e;
	size_t offs = 0;
	uint8_t *out;

	if(pair == NULL)
		return NULL;

	if((pair->public == NULL) || (pair->modulus == NULL))
		return NULL;

	bytes_m = mp_unsigned_bin_size(pair->modulus);
	bytes_e = mp_unsigned_bin_size(pair->public);
	*len = bytes_m + bytes_e + 2 * INT_SIZE;

	if((out = malloc(*len)) == NULL)
		return NULL;

	memcpy(out + offs, &bytes_m, INT_SIZE);		offs += INT_SIZE;
	mp_to_unsigned_bin(pair->modulus, out + offs);	offs += bytes_m;
	memcpy(out + offs, &bytes_e, INT_SIZE);		offs += INT_SIZE;
	mp_to_unsigned_bin(pair->public, out + offs);	offs += bytes_e;

	return out;
}

rsa_keypair_t *rsa_read_public(const uint8_t *data, const size_t len) {
	rsa_keypair_t *out;
	uint32_t bytes_m, bytes_e;
	size_t offs = 0;

	if(checkdata(data, len, 2) == 0) return NULL;
	if((out = emptypublic()) == NULL) return NULL;
	mp_init_multi(out->modulus, out->public, NULL);

	bytes_m = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->modulus, data + offs, bytes_m);	offs += bytes_m;
	bytes_e = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->public, data + offs, bytes_e);	offs += bytes_m;

	out->ksize_bytes = bytes_m;

	return out;
}

uint8_t *rsa_serialize_pair(rsa_keypair_t *pair, size_t *len) {
	uint32_t bytes_m, bytes_e, bytes_d;
	uint32_t bytes_p, bytes_q, bytes_dp, bytes_dq, bytes_qi;
	size_t offs = 0;
	uint8_t *out;

	if(pair == NULL) return NULL;
	if((pair->public == NULL) || (pair->secret == NULL) || (pair->modulus == NULL))
		return NULL;

	bytes_m = mp_unsigned_bin_size(pair->modulus);
	bytes_e = mp_unsigned_bin_size(pair->public);
	bytes_d = mp_unsigned_bin_size(pair->secret);
	*len = bytes_e + bytes_d + bytes_m + 3 * INT_SIZE;

	if((pair->p == NULL) || (pair->q == NULL) || (pair->dp == NULL) || (pair->dq == NULL) || (pair->qi == NULL)) {
		if((out = malloc(*len)) == NULL)
			return NULL;

		memcpy(out + offs, &bytes_m, INT_SIZE);		offs += INT_SIZE;
		mp_to_unsigned_bin(pair->modulus, out + offs); 	offs += bytes_m;
		memcpy(out + offs, &bytes_e, INT_SIZE);		offs += INT_SIZE;
		mp_to_unsigned_bin(pair->public, out + offs);	offs += bytes_e;
		memcpy(out + offs, &bytes_d, INT_SIZE);		offs += INT_SIZE;
		mp_to_unsigned_bin(pair->secret, out + offs);	offs += bytes_d;
		
	} else {
		bytes_p = mp_unsigned_bin_size(pair->p);
		bytes_q = mp_unsigned_bin_size(pair->q);
		bytes_dp = mp_unsigned_bin_size(pair->dp);
		bytes_dq = mp_unsigned_bin_size(pair->dq);
		bytes_qi = mp_unsigned_bin_size(pair->qi);

		*len += bytes_p + bytes_q + bytes_dp + bytes_dq + bytes_qi + 5 * INT_SIZE;

		if((out = malloc(*len)) == NULL)
			return NULL;

		memcpy(out + offs, &bytes_m, INT_SIZE);			offs += INT_SIZE;
		mp_to_unsigned_bin(pair->modulus, out + offs); 	offs += bytes_m;
		memcpy(out + offs, &bytes_e, INT_SIZE);			offs += INT_SIZE;
		mp_to_unsigned_bin(pair->public, out + offs);	offs += bytes_e;
		memcpy(out + offs, &bytes_d, INT_SIZE);			offs += INT_SIZE;
		mp_to_unsigned_bin(pair->secret, out + offs);	offs += bytes_d;
		memcpy(out + offs, &bytes_p, INT_SIZE);			offs += INT_SIZE;
		mp_to_unsigned_bin(pair->p, out + offs); 		offs += bytes_p;
		memcpy(out + offs, &bytes_q, INT_SIZE);			offs += INT_SIZE;
		mp_to_unsigned_bin(pair->q, out + offs); 		offs += bytes_q;
		memcpy(out + offs, &bytes_dp, INT_SIZE);		offs += INT_SIZE;
		mp_to_unsigned_bin(pair->dp, out + offs); 		offs += bytes_dp;
		memcpy(out + offs, &bytes_dq, INT_SIZE);		offs += INT_SIZE;
		mp_to_unsigned_bin(pair->dq, out + offs); 		offs += bytes_dq;
		memcpy(out + offs, &bytes_qi, INT_SIZE);		offs += INT_SIZE;
		mp_to_unsigned_bin(pair->qi, out + offs); 		offs += bytes_qi;
	}
	
	return out;
}

rsa_keypair_t *rsa_read_secret(const uint8_t *data, const size_t len) {
	rsa_keypair_t *out;
	uint32_t bytes_m, bytes_e, bytes_d;
	uint32_t bytes_p, bytes_q, bytes_dp, bytes_dq, bytes_qi;
	size_t offs = 0;

	/* We need to have at least 3 numbers for a valid secret key */
	if(checkdata(data, len, 3) == 0) return 0;
	if((out = emptypair()) == NULL) return NULL;

	mp_init_multi(out->modulus, out->public, out->secret, NULL);

	bytes_m = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->modulus, data + offs, bytes_m);	offs += bytes_m;
	bytes_e = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->public, data + offs, bytes_e);	offs += bytes_e;
	bytes_d = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->secret, data + offs, bytes_d);	offs += bytes_d;

	out->ksize_bytes = bytes_m;

	if((len >= offs) && (checkdata(data + offs, len - offs, 5) != 0)) {
		mp_init_multi(out->p, out->q, out->dp, out->dq, out->qi, NULL);

		bytes_p = *(data + offs);								offs += INT_SIZE;
		mp_read_unsigned_bin(out->p, data + offs, bytes_p);		offs += bytes_p;
		bytes_q = *(data + offs);								offs += INT_SIZE;
		mp_read_unsigned_bin(out->q, data + offs, bytes_q);		offs += bytes_q;
		bytes_dp = *(data + offs);								offs += INT_SIZE;
		mp_read_unsigned_bin(out->dp, data + offs, bytes_dp);	offs += bytes_dp;
		bytes_dq = *(data + offs);								offs += INT_SIZE;
		mp_read_unsigned_bin(out->dq, data + offs, bytes_dq);	offs += bytes_dq;
		bytes_qi = *(data + offs);								offs += INT_SIZE;
		mp_read_unsigned_bin(out->qi, data + offs, bytes_qi);	offs += bytes_qi;
	} else {
		free(out->p);
		free(out->q);
		free(out->dp);
		free(out->dq);
		free(out->qi);

		out->p = out->q = out->dp = out->dq = out->qi = NULL;
	}

	return out;
}

uint8_t *rsa_enc_padded(const uint8_t *data, const size_t inlen, rsa_keypair_t *pair, size_t *outlen) {
	uint8_t *padded, *out = NULL;
	mp_int pt, ct;

	if((padded = oaep(data, inlen, pair->ksize_bytes)) == NULL) return NULL;

	mp_init_multi(&pt, &ct, NULL);
	mp_read_unsigned_bin(&pt, padded, pair->ksize_bytes);
	free(padded);

	if(rsa_enc(&pt, pair, &ct) != MP_OKAY) goto freemp;
	*outlen = mp_unsigned_bin_size(&ct);

	if((out = malloc(*outlen)) == NULL) goto freemp;
	mp_to_unsigned_bin(&ct, out);

freemp:
	mp_clear_multi(&pt, &ct, NULL);
	return out;
}

uint8_t *rsa_dec_padded(const uint8_t *data, size_t inlen, rsa_keypair_t *pair, size_t *outlen) {
	mp_int pt, ct;
	uint8_t *padded, *out = NULL;
	size_t padsize;

	mp_init_multi(&pt, &ct, NULL);
	mp_read_unsigned_bin(&ct, data, inlen);

	if(rsa_dec(&ct, pair, &pt) != MP_OKAY) goto freemp;

	padsize = mp_unsigned_bin_size(&pt);
	if((padded = malloc(pair->ksize_bytes)) == NULL) goto freemp;
	memset(padded, 0, padsize);
	mp_to_unsigned_bin(&pt, padded + (pair->ksize_bytes) - padsize);
	
	out = inv_oaep(padded, padsize, pair->ksize_bytes, outlen);

	free(padded);
freemp:
	mp_clear_multi(&pt, &ct, NULL);
	return out;
}

int rsa_keyid_fromserial(const uint8_t *data, uint8_t *out) {
	uint32_t bytes_m, bytes_e;
	size_t offs = 0;

	if(data == NULL) return 0;

	bytes_m = *(data + offs);	offs += INT_SIZE + bytes_m;
	bytes_e = *(data + offs);	offs += INT_SIZE + bytes_e;

	return sha256(data, offs, out);
}

int rsa_keypair_test(rsa_keypair_t *pair) {
	uint8_t data[AES_KSIZE];
	uint8_t *ct, *pt;
	size_t ctlen, ptlen;
	int ret = 0;
	
	if(getrand(data, AES_KSIZE, NULL) == 0) {
		printf("getrand()");
		return 0;
	}
	if((ct = rsa_enc_padded(data, AES_KSIZE, pair, &ctlen)) == NULL) {
		printf("enc()");
		return 0;
	}
	if((pt = rsa_dec_padded(ct, ctlen, pair, &ptlen)) == NULL) {
		printf("dec()");
		goto freect;
	}
	if(ptlen != AES_KSIZE) {
		printf("size()");
		goto freept;
	}
	if(memcmp(pt, data, AES_KSIZE) != 0) {
		printf("cmp()");
		goto freept;
	}

	ret = 1;
freept:
	free(pt);
freect:
	free(ct);
	return ret;
}

void rsa_keypair_print(rsa_keypair_t *pair) {
	if(pair == NULL) {
		fprintf(stderr, "rsa_keypair_print(): ERROR: Argument is NULL.\n");
		return;
	}

	if(pair->p)			printint(pair->p, "p");
	if(pair->q)			printint(pair->q, "q");
	if(pair->modulus)	printint(pair->modulus, "m");
	if(pair->public)	printint(pair->public, "e");
	if(pair->secret)	printint(pair->secret, "d");
	if(pair->dp) 		printint(pair->dp, "dp");
	if(pair->dq) 		printint(pair->dq, "dq");
	if(pair->qi) 		printint(pair->qi, "qi");
}
