CC = gcc
CFLAGS = -Wall -Wextra
TARGET = easyrev

all: $(TARGET)

$(TARGET): easyrev.c
	$(CC) $(CFLAGS) -o $(TARGET) easyrev.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
