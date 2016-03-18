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

#ifndef OAEP_H_
#define OAEP_H_

#include <stdint.h>
#include <stdlib.h>

#include "rsa.h"
#include "sha256.h"

#define oaep_minsize(msglen)	(((msglen) + (2 * (SHA256_SIZE)) + 2) * 8)

uint8_t *oaep(const uint8_t *msg, const size_t msglen, const size_t modlen);
uint8_t *inv_oaep(const uint8_t *in, const size_t inlen, const size_t modlen, size_t *msglen);

#endif
			
