TARGET = switch

all : $(TARGET)

CC = gcc
LD = gcc
# define LOG_DEBUG to enable debug log
# on OJ my makefile will be replaced so LOG_DEBUG will be undefined
CFLAGS = -g -Wall -Iinclude
LDFLAGS = 

LIBS = -lpthread

SRCS = broadcast.c device_internal.c mac.c main.c

OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS) 

clean:
	rm -f *.o $(TARGET)

compress:
	7z a switch.zip *.c *.h include/*.h Makefile

tags: *.c include/*.h
	ctags *.c include/*.h
