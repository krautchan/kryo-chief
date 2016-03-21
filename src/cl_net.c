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

#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "cl_net.h"
#include "etc.h"
#include "net.h"
#include "sha256.h"

uint8_t *requestforge(const uint8_t msg_type, const uint8_t *keyid, const uint8_t *data, const size_t data_len, size_t *out_len) {
	uint8_t *request;
	uint32_t paksize;
	size_t offs = 0;

	paksize = 1 + data_len + (keyid ? SHA256_SIZE : 0);
	*out_len = paksize + INT_SIZE;

	if((request = malloc(*out_len)) == NULL) return NULL;

	inttoarr(paksize, request);
	offs += INT_SIZE;
	request[offs++] = msg_type;

	if(keyid) {
		memcpy(request + offs, keyid, SHA256_SIZE);
		offs += SHA256_SIZE;
	}
	if(data)
		memcpy(request + offs, data, data_len);

	return request;
}


static int cl_connect(const char *remote_addr, const uint16_t port) {
	int conn_sock;
	struct sockaddr_in addr;
	struct hostent *resolved;
	int i = 0;

	if((resolved = gethostbyname(remote_addr)) == NULL) return INVALID_SOCKET;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if(resolved->h_addr_list[0]) {
		addr.sin_addr.s_addr = *(uint32_t*)resolved->h_addr_list[i];
	} else {
		addr.sin_addr.s_addr = inet_addr(remote_addr);
	}

	if((conn_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) 
		return INVALID_SOCKET;
	if(connect(conn_sock, (struct sockaddr*)(&addr), sizeof(struct sockaddr)) == SOCKET_ERROR) 
		return INVALID_SOCKET;

	return conn_sock;
}

reply_t *cl_sendrecv(const char *remote_addr, const uint16_t port, const uint8_t *data, const size_t len) {
	int conn_sock;
	uint8_t headerbuf[4];
	reply_t *out;

	if((out = malloc(sizeof(reply_t))) == NULL) return NULL;
	if((conn_sock = cl_connect(remote_addr, port)) == INVALID_SOCKET) return NULL;

	if(send(conn_sock, data, len, 0) == -1) return NULL;
	if(recv(conn_sock, headerbuf, 4, 0) == -1) return NULL;

	out->data_len = arrtoint(headerbuf) - 1;

	if((out->data = malloc(out->data_len)) == NULL) goto close;
	if(recv(conn_sock, &(out->msg_type), 1, 0) == -1) goto freeout;
	if(recv(conn_sock, out->data, out->data_len, 0) == -1) goto freedata;

	goto close;

freedata:
	free(out->data);
freeout:
	free(out);
	out = NULL;
close:
	close(conn_sock);
	return out;
}
