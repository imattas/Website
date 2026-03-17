CC = gcc
CFLAGS = -Wall -Wextra
TARGET = angrme

all: $(TARGET)

$(TARGET): angrme.c
	$(CC) $(CFLAGS) -o $(TARGET) angrme.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
