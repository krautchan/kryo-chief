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

#ifndef HTAB_H_
#define HTAB_H_

#include <stdint.h>
#include <stdlib.h>

typedef size_t (*hfunc_t)(const uint8_t *key, const size_t klen);
typedef struct htab_t htab_t;

htab_t *htab_new(const size_t tabsize, hfunc_t hfunc, freefunc_t ffunc);
int htab_insert(htab_t *htab, const uint8_t *key, const size_t klen, void *data);
int htab_delete(htab_t *htab, const uint8_t *key, const size_t klen);
void *htab_lookup(const htab_t *htab, const uint8_t *key, const size_t klen);
void htab_free(htab_t *htab);

#endif
