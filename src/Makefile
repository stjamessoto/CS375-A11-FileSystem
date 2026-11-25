# Makefile for CS375 Lab A11 - simplefs
CC      = gcc
CFLAGS  = -Wall -Wextra -std=gnu11 -O2 -g

all: fs_test

fs_test: simplefs.c fs_test.c simplefs.h
	$(CC) $(CFLAGS) -o fs_test simplefs.c fs_test.c

run: fs_test
	./fs_test

clean:
	rm -f fs_test

.PHONY: all run clean
