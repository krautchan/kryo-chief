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

#include <tommath.h>

#include "etc.h"
#include "oaep.h"
#include "rsa_int.h"

static int mp_good_pq(mp_int *p, mp_int *q, mp_int *n) {
	mp_int diff, mindiff, two;
	int ret;

	mp_init_multi(&diff, &mindiff, NULL);
	mp_init_set_int(&two, 2);

	mp_sqrt(n, &mindiff);
	mp_sqrt(&mindiff, &mindiff);
	mp_mul(&mindiff, &two, &mindiff);

	if(mp_cmp(p, q) == MP_GT)
		mp_sub(p, q, &diff);
	else
		mp_sub(q, p, &diff);

	if(mp_cmp(&diff, &mindiff) == MP_GT)
		ret = MP_YES;
	else
		ret = MP_NO;

	mp_clear_multi(&diff, &mindiff, &two, NULL);

	return ret;
}

static int mp_phi(mp_int *p, mp_int *q, mp_int *out) {
	mp_int one, p1, q1;
	int ret;

	if((ret = mp_init_multi(&p1, &q1, NULL)) != MP_OKAY) goto end;
	if((ret = mp_init_set_int(&one, 1)) != MP_OKAY) goto clearpq;
	if((ret = mp_sub(p, &one, &p1)) != MP_OKAY) goto clearall;
	if((ret = mp_sub(q, &one, &q1)) != MP_OKAY) goto clearall;
	if((ret = mp_mul(&p1, &q1, out)) != MP_OKAY) goto clearall;

clearall:
	mp_clear(&one);
clearpq:
	mp_clear_multi(&p1, &q1, NULL);
end:
	return ret;
}

static void rsa_dec_help(rsa_keypair_t *pair) {
	mp_int p1, q1, one;

	if(pair == NULL)
		return;

	pair->dp = NULL;
	pair->dq = NULL;
	pair->qi = NULL;

	if(mp_init_multi(&p1, &q1, NULL) != MP_OKAY) goto end;
	if(mp_init_set_int(&one, 1) != MP_OKAY) goto freepq;
	if((pair->dp = malloc(sizeof(mp_int))) == NULL) goto freeone;
	if((pair->dq = malloc(sizeof(mp_int))) == NULL) goto freedp;
	if((pair->qi = malloc(sizeof(mp_int))) == NULL) goto freedq;

	if(mp_init_multi(pair->dp, pair->dq, pair->qi, NULL) != MP_OKAY) goto freeqi;
	if(mp_sub(pair->p, &one, &p1) != MP_OKAY) goto freeqi;
	if(mp_sub(pair->q, &one, &q1) != MP_OKAY) goto freeqi;
	if(mp_mod(pair->secret, &p1, pair->dp) != MP_OKAY) goto freeqi;
	if(mp_mod(pair->secret, &q1, pair->dq) != MP_OKAY) goto freeqi;
	if(mp_invmod(pair->q, pair->p, pair->qi) != MP_OKAY) goto freeqi;

	mp_clear_multi(&p1, &q1, &one, NULL);
	return;

freeqi:
	free(pair->qi);
	pair->qi = NULL;
freedq:
	free(pair->dq);
	pair->dp = NULL;
freedp:
	free(pair->dp);
	pair->dp = NULL;
freeone:
	mp_clear(&one);
freepq:
	mp_clear_multi(&p1, &q1, NULL);
end:
	return;
}

rsa_keypair_t *rsa_keypair_gen(const int n_bits, int *status) {
	int n_tests;
	mp_int phi;
	rsa_keypair_t *out;
	size_t actual_size = bitstobytes(n_bits) * 8;

	if((*status = mp_init(&phi)) != MP_OKAY) return NULL;
	if((out = malloc(sizeof(rsa_keypair_t))) == NULL) goto freephi;
	if((out->modulus = malloc(sizeof(mp_int))) == NULL) goto freeout;
	if((out->public = malloc(sizeof(mp_int))) == NULL) goto freemod;
	if((out->secret = malloc(sizeof(mp_int))) == NULL) goto freepub;
	if((out->p = malloc(sizeof(mp_int))) == NULL) goto freesec;
	if((out->q = malloc(sizeof(mp_int))) == NULL) goto freep;

	if((*status = mp_init_multi(out->modulus, out->secret, out->p, out->q, NULL)) != MP_OKAY) goto freeq;
	if((*status = mp_init_set_int(out->public, 65537)) != MP_OKAY) goto freeint;

	n_tests = mp_prime_rabin_miller_trials(actual_size);

	do {
		if((*status = mp_prime_random_ex(out->p, n_tests, actual_size / 2, LTM_PRIME_SAFE, getrand, NULL)) != MP_OKAY) goto freeall;
		if((*status = mp_prime_random_ex(out->q, n_tests, actual_size / 2, LTM_PRIME_SAFE, getrand, NULL)) != MP_OKAY) goto freeall;
		if((*status = mp_mul(out->p, out->q, out->modulus)) != MP_OKAY) goto freeall;
	} while((*status = mp_good_pq(out->p, out->q, out->modulus)) == MP_NO);

	if((*status = mp_phi(out->p, out->q, &phi)) != MP_OKAY) goto freeall;
	if((*status = mp_invmod(out->public, &phi, out->secret)) != MP_OKAY) goto freeall;

	rsa_dec_help(out);

	out->ksize_bytes = actual_size / 8;

	*status = MP_OKAY;
	mp_clear(&phi);
	return out;

freeall:
	mp_clear(out->public);
freeint:
	mp_clear_multi(out->modulus, out->secret, out->p, out->q, NULL);
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
freeout:
	free(out);
freephi:
	mp_clear(&phi);
	return NULL;
}

void rsa_keypair_free(rsa_keypair_t *pair) {
	if(pair == NULL)
		return;

	if(pair->modulus) mp_clear(pair->modulus);
	if(pair->public) mp_clear(pair->public);
	if(pair->secret) mp_clear(pair->secret);
	if(pair->p) mp_clear(pair->p);
	if(pair->q) mp_clear(pair->q);
	if(pair->dp) mp_clear(pair->dp);
	if(pair->dq) mp_clear(pair->dq);
	if(pair->qi) mp_clear(pair->qi);

	free(pair->modulus);
	free(pair->public);
	free(pair->secret);
	free(pair->p);
	free(pair->q);
	free(pair->dp);
	free(pair->dq);
	free(pair->qi);

	free(pair);
}

int rsa_enc(mp_int *p, rsa_keypair_t *pair, mp_int *c) {
	if((p == NULL) || (pair == NULL) || (c == NULL))
		return MP_VAL;

	return mp_exptmod(p, pair->public, pair->modulus, c);
}

int rsa_dec(mp_int *c, rsa_keypair_t *pair, mp_int *p) {
	mp_int m1, m2, h, diff;

	if((c == NULL) || (pair == NULL) || (p == NULL))
		return MP_VAL;

	if((pair->dp != NULL) && (pair->dq != NULL) && (pair->qi != NULL)) {
		/* Fast mode */
		
		if(mp_init_multi(&m1, &m2, &h, &diff, NULL) != MP_OKAY) goto slow;
		if(mp_exptmod(c, pair->dp, pair->p, &m1) != MP_OKAY) goto failed;
		if(mp_exptmod(c, pair->dq, pair->q, &m2) != MP_OKAY) goto failed;
		if(mp_sub(&m1, &m2, &diff) != MP_OKAY) goto failed;
		if(mp_mul(&diff, pair->qi, &h) != MP_OKAY) goto failed;
		if(mp_mod(&h, pair->p, &h) != MP_OKAY) goto failed;
		if(mp_mul(&h, pair->q, &m1) != MP_OKAY) goto failed;
		if(mp_add(&m1, &m2, p) == MP_OKAY) goto failed;

		mp_clear_multi(&m1, &m2, &h, &diff, NULL);
		return MP_OKAY;
failed:
		mp_clear_multi(&m1, &m2, &h, &diff, NULL);
		goto slow;
	} else {
slow:
		/* Slow mode */
		return mp_exptmod(c, pair->secret, pair->modulus, p);
	}
}
