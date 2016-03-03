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
		$(OBJ)/ccard.o \
		$(OBJ)/client.o \
		$(OBJ)/cl_net.o \
		$(OBJ)/dynarr.o \
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

CTEST_OBJS=$(OBJ)/ccard.o $(OBJ)/cc_test.o $(OBJ)/dynarr.o $(OBJ)/etc.o
AESTEST_OBJS=$(OBJ)/aes.o $(OBJ)/aestest.o
RSATEST_OBJS=$(OBJ)/etc.o \
			 $(OBJ)/oaep.o \
			 $(OBJ)/rc4.o \
			 $(OBJ)/rsa.o \
			 $(OBJ)/rsa_io.o \
			 $(OBJ)/rsatest.o\
			 $(OBJ)/sha256.o \

default: $(BIN)/client $(BIN)/server

all: $(BIN)/aestest $(BIN)/client $(BIN)/server $(BIN)/cc_test $(BIN)/rsatest

$(BIN)/aestest: $(AESTEST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/client: $(CL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/server: $(SV_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS_SV) -o $@ $^

$(BIN)/cc_test: $(CTEST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BIN)/rsatest: $(RSATEST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f $(OBJ)/*
	rm -f $(BIN)/*

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c -o $@ $^
