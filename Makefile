CC=clang
CFLAGS=-Wall -Wextra -Werror -Wpedantic -g

ws: build 
	./bin/ws

build: ws.c sha1.c
	$(CC) $(CFLAGS) -o bin/ws ws.c sha1.c base64.c
