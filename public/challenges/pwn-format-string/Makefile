CC = gcc
CFLAGS = -fno-stack-protector -no-pie -Wno-format-security
TARGET = fmtstr

all: $(TARGET)

$(TARGET): fmtstr.c
	$(CC) $(CFLAGS) -o $(TARGET) fmtstr.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
