CC=clang
CFLAGS=-Wall -Wextra -Werror -Wpedantic -g

ws: build 
	./bin/ws

build: ws.c
	$(CC) $(CFLAGS) -o bin/ws ws.c
