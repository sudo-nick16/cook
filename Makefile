CC=clang++ -std=c++11
# CFLAGS=-Wall -Wextra -Werror -Wpedantic -g

example: 
	$(CC) $(CFLAGS) -o bin/example ./examples/chat-room/main.cpp ws.c sha1.c base64.c
	./bin/example

ws: build 
	./bin/ws

build: ws.c sha1.c
	$(CC) $(CFLAGS) -o bin/ws ws.c sha1.c base64.c
