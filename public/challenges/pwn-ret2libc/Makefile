CC = gcc
# NX (non-executable stack) is enabled by default -- no -z execstack
CFLAGS = -fno-stack-protector -no-pie
TARGET = ret2libc

all: $(TARGET)

$(TARGET): ret2libc.c
	$(CC) $(CFLAGS) -o $(TARGET) ret2libc.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
