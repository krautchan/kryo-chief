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

#ifndef CL_NET_H_
#define CL_NET_H_

#include <stdint.h>
#include <stdlib.h>

typedef struct reply_t {
	size_t data_len;
	uint8_t msg_type;
	uint8_t *data;
} reply_t;

uint8_t *requestforge(const uint8_t msg_type, const uint8_t *keyid, const uint8_t *data, const size_t data_len, size_t *out_len);
reply_t *cl_sendrecv(const char *remote_addr, const uint16_t port, const uint8_t *data, const size_t len);

#endif
