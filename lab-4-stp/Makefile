TARGET := stp

all : $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Iinclude
LDFLAGS = 

LIBS = -lpthread

SRCS = stp.c stp_timer.c main.c device_internal.c

OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS) 

compress:
	7z a stp.zip *.c *.h include/*.h Makefile

clean:
	rm -f *.o $(TARGET)
	rm *.txt

tags: *.c include/*.h
	ctags *.c include/*.h
