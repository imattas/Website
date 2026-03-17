CC = gcc
CFLAGS = -fno-stack-protector -no-pie -z execstack
TARGET = overflow

all: $(TARGET)

$(TARGET): overflow.c
	$(CC) $(CFLAGS) -o $(TARGET) overflow.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
