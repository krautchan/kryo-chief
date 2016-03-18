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

#ifndef RSA_IO_H_
#define RSA_IO_H_

#include "rsa.h"

#define INT_SIZE	sizeof(uint32_t)

uint8_t *rsa_serialize_public(rsa_keypair_t *pair, size_t *len);
rsa_keypair_t *rsa_read_public(const uint8_t *data, const size_t len);

uint8_t *rsa_serialize_pair(rsa_keypair_t *pair, size_t *len);
rsa_keypair_t *rsa_read_secret(const uint8_t *data, const size_t len);

uint8_t *rsa_enc_padded(const uint8_t *data, const size_t inlen, rsa_keypair_t *pair, size_t *outlen);
uint8_t *rsa_dec_padded(const uint8_t *data, const size_t inlen, rsa_keypair_t *pair, size_t *outlen);

int rsa_keyid_fromserial(const uint8_t *data, uint8_t *out);

int rsa_keypair_test(rsa_keypair_t *pair);

void rsa_keypair_print(rsa_keypair_t *pair);

#endif
