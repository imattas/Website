CC = gcc
CFLAGS = -Wall -Wextra -O0
TARGET = obfuscated

all: $(TARGET)

# Compile with -O0 to prevent the compiler from optimizing away
# the control flow flattening and opaque predicates
$(TARGET): obfuscated.c
	$(CC) $(CFLAGS) -o $(TARGET) obfuscated.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
