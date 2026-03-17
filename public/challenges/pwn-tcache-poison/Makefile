CC = gcc
CFLAGS = -fno-stack-protector -no-pie
TARGET = tcache

all: $(TARGET)

$(TARGET): tcache.c
	$(CC) $(CFLAGS) -o $(TARGET) tcache.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
