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

#ifndef DYNARR_H_
#define DYNARR_H_

#include <stdlib.h>

#include "etc.h"

typedef struct dynarr_t dynarr_t;

dynarr_t *dynarr_new(const size_t size_entry, const size_t prealloc, freefunc_t ffunc);
int dynarr_add(dynarr_t *arr, void *data);
size_t dynarr_get_size(const dynarr_t *arr);
void *dynarr_get_index(const dynarr_t *arr, const size_t idx);
void dynarr_free(dynarr_t *arr);

#endif
