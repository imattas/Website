CC = gcc
CFLAGS = -fno-stack-protector -no-pie
TARGET = pivot

all: $(TARGET)

$(TARGET): pivot.c
	$(CC) $(CFLAGS) -o $(TARGET) pivot.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
