all: http-server

http-server: *.c
	gcc -Wall -g *.c -o http-server -lssl -lcrypto -lpthread

compress:
	7z a http-server.zip *.c *.h Makefile

clean:
	@rm http-server
