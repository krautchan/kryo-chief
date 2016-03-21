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

#include <stdio.h>
#include <string.h>

#include "dynarr.h"
#include "etc.h"

struct dynarr_t {
	size_t size_entry;
	size_t prealloc, n_alloced, n_entries;
	freefunc_t free;
	void *data;
};

dynarr_t *dynarr_new(const size_t size_entry, const size_t prealloc, freefunc_t ffunc) {
	dynarr_t *out;

	if((out = malloc(sizeof(dynarr_t))) == NULL) return NULL;
	if((out->data = malloc(prealloc * size_entry)) == NULL) {
		free(out);
		return NULL;
	}

	out->size_entry = size_entry;
	out->prealloc = prealloc;
	out->n_alloced = prealloc;
	out->n_entries = 0;
	out->free = ffunc;

	return out;
}

int dynarr_add(dynarr_t *arr, void *data) {
	void *newdata;
	size_t size_copy, write_offset;

	if((arr == NULL) || (data == NULL))
		return 0;

	if(arr->n_entries == arr->n_alloced) {
		if((newdata = malloc((arr->n_alloced + arr->prealloc) * arr->size_entry)) == NULL)
			return 0;

		size_copy = arr->n_alloced * arr->size_entry;
		memcpy(newdata, arr->data, size_copy);

		free(arr->data);
		arr->data = newdata;
		arr->n_alloced += arr->prealloc;
	}

	write_offset = arr->n_entries * arr->size_entry;
	memcpy((char*)(arr->data) + write_offset, data, arr->size_entry);
	arr->n_entries++;

	return 1;
}

size_t dynarr_get_size(const dynarr_t *arr) {
	if(arr == NULL)
		return 0;

	return arr->n_entries;
}

void *dynarr_get_index(const dynarr_t *arr, const size_t idx) {
	size_t read_offs;

	if(arr == NULL) return NULL;
	if(idx >= arr->n_entries) return NULL;

	read_offs = idx * arr->size_entry;
	return (char*)(arr->data) + read_offs;
}

void dynarr_free(dynarr_t *arr) {
	size_t i;
	void *data;
	
	if(arr == NULL)	return;

	if(arr->free) {
		for(i = 0; i < arr->n_entries; i++) {
			data = dynarr_get_index(arr, i);
			arr->free(data);
		}
	}

	free(arr->data);
	free(arr);
}
