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

#ifndef RC4_H_
#define RC4_H_

#include <stdint.h>
#include <stdlib.h>

typedef struct rc4_ctx_t {
	uint8_t idx1, idx2;
	uint8_t table[256];
} rc4_ctx_t;

#define rc4_drop(ctx, n) rc4_gen((ctx), NULL, (n))

void rc4_init(rc4_ctx_t *ctx, const uint8_t *key, const size_t len);
void rc4_gen(rc4_ctx_t *ctx, uint8_t *stream, const size_t len);

#endif
