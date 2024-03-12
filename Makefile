CC=clang
CFLAGS=-Wall -Wextra -Werror -Wpedantic -g

example: 
	clang++ -std=c++11 -o bin/example ./examples/chat-room/main.cpp ws.c sha1.c
	./bin/example

ws: build 
	./bin/ws

build: ws.c sha1.c
	$(CC) $(CFLAGS) -o bin/ws ws.c sha1.c
