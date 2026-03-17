CC = gcc
CFLAGS = -Wall -Wextra
TARGET = crackme

all: $(TARGET)

$(TARGET): crackme.c
	$(CC) $(CFLAGS) -o $(TARGET) crackme.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
