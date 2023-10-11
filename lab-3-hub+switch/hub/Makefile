all: hub

hub: main.c broadcast.c device_internal.c
	gcc -Iinclude/ -Wall -DLOG_DEBUG -g main.c broadcast.c device_internal.c -o hub

clean:
	@rm -f hub

compress:
	7z a broadcast.zip *.c include/*.h Makefile
