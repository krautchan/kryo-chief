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

#ifndef RSA_H_
#define RSA_H_

#include <tommath.h>

typedef struct rsa_keypair_t rsa_keypair_t;

rsa_keypair_t *rsa_keypair_gen(const int n_bits, int *status);
void rsa_keypair_free(rsa_keypair_t *pair);

int rsa_enc(mp_int *p, rsa_keypair_t *pair, mp_int *c);
int rsa_dec(mp_int *c, rsa_keypair_t *pair, mp_int *p);

#endif
