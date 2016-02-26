#include <stdint.h>
#include <stdlib.h>

#include <tommath.h>

#include "etc.h"
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

	if((out = emptypublic()) == NULL) return NULL;
	mp_init_multi(out->modulus, out->public, NULL);

	/* Validate or crash! */
	bytes_m = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->modulus, data + offs, bytes_m);	offs += bytes_m;
	bytes_e = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->public, data + offs, bytes_e);	offs += bytes_m;

	return out;
}

uint8_t *rsa_serialize_pair(rsa_keypair_t *pair, size_t *len) {
	uint32_t bytes_m, bytes_e, bytes_d;
	uint32_t bytes_p, bytes_q, bytes_dp, bytes_dq, bytes_qi;
	size_t offs = 0;
	uint8_t *out;

	if(pair == NULL)
		return NULL;

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

	if((out = emptypair()) == NULL) return NULL;
	mp_init_multi(out->modulus, out->public, out->secret, NULL);

	/* Validate or crash! */
	bytes_m = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->modulus, data + offs, bytes_m);	offs += bytes_m;
	bytes_e = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->public, data + offs, bytes_e);	offs += bytes_e;
	bytes_d = *(data + offs);									offs += INT_SIZE;
	mp_read_unsigned_bin(out->secret, data + offs, bytes_d);	offs += bytes_d;

	/* Assume all additional values are present. Bad assumption. */
	if(len - offs > 0) {
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

	if((padded = oaep(data, inlen, KEYSIZE)) == NULL)
		return NULL;

	mp_init_multi(&pt, &ct, NULL);
	mp_read_unsigned_bin(&pt, padded, PADSIZE);
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
	uint8_t padded[PADSIZE], *out = NULL;
	size_t padsize;

	mp_init_multi(&pt, &ct, NULL);
	mp_read_unsigned_bin(&ct, data, inlen);

	if(rsa_dec(&ct, pair, &pt) != MP_OKAY) goto freemp;

	padsize = mp_unsigned_bin_size(&pt);
	memset(padded, 0, PADSIZE);
	mp_to_unsigned_bin(&pt, padded + PADSIZE - padsize);
	
	out = inv_oaep(padded, KEYSIZE, outlen);

freemp:
	mp_clear_multi(&pt, &ct, NULL);
	return out;
}

uint8_t *rsa_keyid_fromserial(const uint8_t *data) {
	uint32_t bytes_m, bytes_e;
	size_t offs = 0;
	sha256_t hash;

	if(data == NULL)
		return NULL;

	bytes_m = *(data + offs);	offs += INT_SIZE + bytes_m;
	bytes_e = *(data + offs);	offs += INT_SIZE + bytes_e;

	hash = sha256(data, offs);

	return hash.string;
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
