CC = gcc
CFLAGS = -fno-stack-protector -no-pie
TARGET = rop

all: $(TARGET)

$(TARGET): rop.c
	$(CC) $(CFLAGS) -o $(TARGET) rop.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
