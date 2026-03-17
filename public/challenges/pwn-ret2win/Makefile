CC = gcc
CFLAGS = -fno-stack-protector -no-pie
TARGET = ret2win

all: $(TARGET)

$(TARGET): ret2win.c
	$(CC) $(CFLAGS) -o $(TARGET) ret2win.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
