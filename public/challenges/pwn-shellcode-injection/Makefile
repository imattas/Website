CC = gcc
CFLAGS = -fno-stack-protector -no-pie -z execstack
TARGET = shellcode

all: $(TARGET)

$(TARGET): shellcode.c
	$(CC) $(CFLAGS) -o $(TARGET) shellcode.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
