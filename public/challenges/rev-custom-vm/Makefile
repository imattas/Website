CC = gcc
CFLAGS = -Wall -Wextra
TARGET = vm

all: $(TARGET)

$(TARGET): vm.c
	$(CC) $(CFLAGS) -o $(TARGET) vm.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
