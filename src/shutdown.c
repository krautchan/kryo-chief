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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cl_net.h"
#include "config.h"
#include "etc.h"
#include "protocol.h"

#define MODE_NONE	0
#define MODE_FILE	1
#define MODE_INTER	2
#define MODE_CMDL	4

static int send_password(const char *password, const size_t len) {
	uint8_t *packet;
	size_t paksize = len + 5;
	uint8_t *reply;
	int ret = EXIT_FAILURE;

	if((packet = malloc(paksize)) == NULL)
		return ret;

	inttoarr(len + 1, packet);
	packet[4] = NET_CTL_SHUTDOWN;
	memcpy(packet + 5, password, len);

	printf("Using password '%s'.\n", password);
	printf("Sending shutdown request to %s:%d...\n", CONFIG_SV_ADDR, CONFIG_SV_PORT);

	if((reply = cl_oneshot(CONFIG_SV_ADDR, CONFIG_SV_PORT, packet, paksize, NULL)) != NULL)
			ret = EXIT_SUCCESS;

	free(packet);
	return ret;
}

static int read_password(void) {
	char *password;
	int ret;

	if((password = line_in(stdin)) == NULL)
		return EXIT_FAILURE;
	ret = send_password(password, strlen(password));

	free(password);

	return ret;
}

static int file_password(char *filename) {
	FILE *fp;
	char *password;
	int ret;

	if((fp = fopen(filename, "rb")) == NULL) {
		fprintf(stderr, "ERROR: fopen(%s) failed.\n", filename);
		return EXIT_FAILURE;
	}
	if((password = line_in(fp)) == NULL)
		return EXIT_FAILURE;
	fclose(fp);

	ret = send_password(password, strlen(password));
	free(password);
	
	return ret;
}

static int usage(char *arg) {
	printf("Server shutdown tool.\n");
	printf("USAGE: %s [-f <file>] [-p <password>] [-i]\n", arg);
	printf("\t-f\tRead password from <file>\n");
	printf("\t-p\tUse <password> from commandline\n");
	printf("\t-i\tRead the password from stdin\n");
	return EXIT_FAILURE;
}

int main(int argc, char **argv) {
	int opt, options = 0, mode = MODE_NONE;
	char *source = NULL;

	while((opt = getopt(argc, argv, "f:ip:")) != -1) {
		switch(opt) {
			case 'f':
				mode |= MODE_FILE;
				source = optarg;
				options++;
				break;
			case 'i':
				mode |= MODE_INTER;
				options++;
				break;
			case 'p':
				mode |= MODE_CMDL;
				source = optarg;
				options++;
				break;
			default:
				return usage(argv[0]);
		}
	}

	if(options > 1) return usage(argv[0]);

	switch(mode) {
		case MODE_NONE:
			return file_password(CONFIG_DATADIR "shutdown_pass");
		case MODE_FILE:
			return file_password(source);
		case MODE_INTER:
			return read_password();
		case MODE_CMDL:
			return send_password(source, strlen(source));
	}

	return EXIT_SUCCESS;
}
