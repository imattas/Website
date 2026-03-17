CC = gcc
CFLAGS = -Wall -Wextra
TARGET = xorrev

all: $(TARGET)

$(TARGET): xorrev.c
	$(CC) $(CFLAGS) -o $(TARGET) xorrev.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
