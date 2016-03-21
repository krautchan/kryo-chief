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

#ifndef ETC_H_
#define ETC_H_

#include <stdint.h>
#include <stdlib.h>

#include <tommath.h>

#define INT_SIZE       (sizeof(uint32_t))

typedef void (*freefunc_t)(void*);

void printaddr(const uint8_t *peer);
void inttoarr(const uint32_t in, uint8_t *out);
uint32_t arrtoint(uint8_t *in);
size_t bitstobytes(const size_t n_bits);
size_t fp_size(FILE *fp);
char *alloc_copy(const char *str);
void xorblock(uint8_t *dat1, uint8_t *dat2, size_t len);
int getrand(uint8_t *dst, int len, void *dat);
void printint(mp_int *i, const char *id);
char *line_in(FILE *fp);

#endif
