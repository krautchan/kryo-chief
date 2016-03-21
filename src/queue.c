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

typedef struct queue_entry_t {
	struct queue_entry_t *prev, *next;
	void *data;
} queue_entry_t;

typedef struct queue_t {
	struct queue_entry_t *first, *last;
	size_t n_entries;
} queue_t;

queue_t *queue_new(void) {
	queue_t *out;

	if((out = malloc(sizeof(queue_t))) == NULL) return NULL;

	out->first = NULL;
	out->last = NULL;
	out->n_entries = 0;

	return out;
}

static queue_entry_t *queue_entry_new(void *data, queue_entry_t *prev, queue_entry_t *next) {
	queue_entry_t *out;

	if((out = malloc(sizeof(queue_t))) == NULL) return NULL;

	out->data = data;
	out->prev = prev;
	out->next = next;

	return out;
}

int queue_push(queue_t *queue, void *data) {
	queue_entry_t *newent;

	if(queue == NULL) return 0;

	if(queue->n_entries == 0) {
		if((newent = queue_entry_new(data, NULL, NULL)) == NULL)
			return 0;
		queue->first = newent;
		queue->last = newent;
		queue->n_entries++;
	} else {
		if((newent = queue_entry_new(data, queue->last, NULL)) == NULL)
			return 0;
		queue->last->next = newent;
		queue->last = newent;
		queue->n_entries++;
	}
	return 1;
}

void *queue_pull(queue_t *queue) {
	void *out;
	queue_entry_t *first;
	
	if(queue == NULL) return NULL;
	if(queue->n_entries == 0) return NULL;
	if((first = queue->first) == NULL) return NULL;

	out = first->data;
	queue->first = first->next;
	free(first);

	if(queue->first)
		queue->first->prev = NULL;

	queue->n_entries--;
	return out;
}

void queue_free(queue_t *queue) {
	queue_entry_t *curr, *next;

	if(queue == NULL) return;

	curr = queue->first;
	while(curr) {
		next = curr->next;
		free(curr);
		curr = next;
	}

	free(queue);
}

size_t queue_get_size(const queue_t *queue) {
	if(queue == NULL) return 0;
	return queue->n_entries;
}
