CC = gcc
CFLAGS = -Wall -Wextra
TARGET = antidebug

all: $(TARGET)

$(TARGET): antidebug.c
	$(CC) $(CFLAGS) -o $(TARGET) antidebug.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
