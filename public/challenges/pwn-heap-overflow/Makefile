CC = gcc
CFLAGS = -fno-stack-protector -no-pie
TARGET = heap

all: $(TARGET)

$(TARGET): heap.c
	$(CC) $(CFLAGS) -o $(TARGET) heap.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
