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

#ifndef CCARD_H_
#define CCARD_H_

#include <stdint.h>
#include <stdlib.h>

#define CC_OK		1
#define CC_UNSURE	0
#define CC_BLIST	-1
#define CC_WLIST	-2
#define CC_LENGTH	-3
#define CC_CKSUM	-4
#define CC_KNOWN	-5

void cc_freelists(void);
void cc_save(const uint8_t *num, const size_t len, const char *filename);
int cc_check(const uint8_t *num, const size_t len, char *realcheck);

#endif
