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

#include "etc.h"
#include "hfuncs.h"
#include "htab.h"

typedef struct htab_node_t {
	void *data;
	uint8_t *key;
	size_t klen;
	struct htab_node_t *next;
} htab_node_t;

struct htab_t {
	size_t tabsize;
	htab_node_t **table;
	hfunc_t hfunc;
	freefunc_t ffunc;
};

htab_t *htab_new(const size_t tabsize, hfunc_t hfunc, freefunc_t ffunc) {
	htab_t *out;
	size_t i;

	if(tabsize == 0) return NULL;
	if((out = malloc(sizeof(htab_t))) == NULL) return NULL;
	if((out->table = malloc(tabsize * sizeof(htab_node_t*))) == NULL) {
		free(out);
		return NULL;
	}
	
	for(i = 0; i < tabsize; i++)
		out->table[i] = NULL;

	if(hfunc == NULL)
		out->hfunc = DEFAULT_HFUNC;
	else
		out->hfunc = hfunc;

	out->ffunc = ffunc;
	out->tabsize = tabsize;

	return out;
}

int htab_insert(htab_t *htab, const uint8_t *key, const size_t klen, void *data) {
	size_t index;
	htab_node_t *newnode;

	if(htab == NULL) return 0;
	if(key == NULL) return 0;
	if((newnode = malloc(sizeof(htab_node_t))) == NULL) return 0;
	if((newnode->key = malloc(klen)) == NULL) {
		free(newnode);
		return 0;
	}

	index = htab->hfunc(key, klen) % htab->tabsize;
	memcpy(newnode->key, key, klen);
	newnode->klen = klen;
	newnode->data = data;
	newnode->next = htab->table[index];
	htab->table[index] = newnode;

	return 1;
}

int htab_delete(htab_t *htab, const uint8_t *key, const size_t klen) {
	size_t index;
	int ret;
	htab_node_t *currnode, *nextnode, *last = NULL;

	if(htab == NULL) return 0;
	if(key == NULL) return 0;

	index = htab->hfunc(key, klen) % htab->tabsize;

	currnode = htab->table[index];
	ret = 0;

	while(currnode) {
		if((currnode->klen == klen) && (!memcmp(currnode->key, key, klen))) {
			if(last != NULL)
				last->next = currnode->next;
			else
				htab->table[index] = currnode->next;

			htab->ffunc(currnode->data);
			nextnode = currnode->next;
			free(currnode->key);
			free(currnode);
			currnode = nextnode;

			ret = 1;
		} else {
			last = currnode;
			currnode = currnode->next;
		}
	}

	return ret;
}

void *htab_lookup(const htab_t *htab, const uint8_t *key, const size_t klen) {
	size_t index;
	htab_node_t *currnode;

	if(htab == NULL) return NULL;
	if(key == NULL) return NULL;

	index = htab->hfunc(key, klen) % htab->tabsize;
	currnode = htab->table[index];

	while(currnode) {
		if((currnode->klen == klen) && (!memcmp(currnode->key, key, klen)))
			return currnode->data;
		currnode = currnode->next;
	}

	return NULL;
}

static void freenode(freefunc_t ffunc, htab_node_t *node) {
	htab_node_t *next;

	while(node) {
		next = node->next;
		if(ffunc)
			ffunc(node->data);
		free(node->key);
		free(node);
		node = next;
	}
}

void htab_free(htab_t *htab) {
	size_t i;
	htab_node_t *currnode;

	if(htab == NULL) return;

	for(i = 0; i < htab->tabsize; i++) {
		currnode = htab->table[i];
		freenode(htab->ffunc, currnode);
	}

	free(htab->table);
	free(htab);
}
