CC = gcc
CFLAGS = -Wall -Wextra
TARGET = patchme

all: $(TARGET)

$(TARGET): patchme.c
	$(CC) $(CFLAGS) -o $(TARGET) patchme.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
