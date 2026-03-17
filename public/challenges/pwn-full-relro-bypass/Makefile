CC = gcc
CFLAGS = -fno-stack-protector -pie -fPIE -Wl,-z,relro,-z,now
TARGET = fullrelro

all: $(TARGET)

$(TARGET): fullrelro.c
	$(CC) $(CFLAGS) -o $(TARGET) fullrelro.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
