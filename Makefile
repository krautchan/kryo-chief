## 
## HTR -- The Heisetrolljan
## 
## Copyright (C) 2016  Martin Wolters
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to 
## the Free Software Foundation, Inc.
## 51 Franklin Street, Fifth Floor
## Boston, MA  02110-1301, USA
## 

SRC=src
INC=include
OBJ=objects
BIN=bin

CFLAGS=-I$(INC) -O0 -ggdb -Wall
#CFLAGS=-I$(INC) -O2 -Wall
LDFLAGS=-ltommath
LDFLAGS_SV=-ltommath -lpthread

CC=gcc

CL_OBJS=$(OBJ)/aes.o \
		$(OBJ)/client.o \
		$(OBJ)/cl_net.o \
		$(OBJ)/etc.o \
		$(OBJ)/filecrypt.o \
		$(OBJ)/fslist.o \
		$(OBJ)/oaep.o \
		$(OBJ)/rc4.o \
		$(OBJ)/rsa.o \
		$(OBJ)/rsa_io.o \
		$(OBJ)/sha256.o

SV_OBJS=$(OBJ)/ccard.o \
		$(OBJ)/dynarr.o \
		$(OBJ)/etc.o \
		$(OBJ)/fslist.o \
		$(OBJ)/hfuncs.o \
		$(OBJ)/htab.o \
		$(OBJ)/oaep.o \
		$(OBJ)/queue.o \
		$(OBJ)/rc4.o \
		$(OBJ)/rsa.o \
		$(OBJ)/rsa_io.o \
		$(OBJ)/server.o \
		$(OBJ)/sv_keydb.o \
		$(OBJ)/sv_net.o \
		$(OBJ)/sha256.o

SD_OBJS=$(OBJ)/cl_net.o \
		$(OBJ)/etc.o \
		$(OBJ)/shutdown.o

CT_OBJS=$(OBJ)/ccard.o $(OBJ)/cc_test.o $(OBJ)/dynarr.o $(OBJ)/etc.o

all: $(BIN)/gettok $(BIN)/client $(BIN)/server $(BIN)/shutdown

$(BIN)/gettok: $(SRC)/extract_tokens.c
	$(CC) $(CFLAGS) -o $@ $^

$(BIN)/client: $(CL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/server: $(SV_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS_SV) -o $@ $^

$(BIN)/shutdown: $(SD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/cc_test: $(CT_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f $(OBJ)/*
	rm -f $(BIN)/*

mrproper: clean
	cp .config_default .config
	rm -f etc/keys_issued
	rm -f etc/keys_released
	rm -f etc/release_tokens

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c -o $@ $^
