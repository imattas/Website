AS = as
LD = ld
TARGET = srop

all: $(TARGET)

$(TARGET): srop.o
	$(LD) -o $(TARGET) srop.o

srop.o: srop.S
	$(AS) -o srop.o srop.S

clean:
	rm -f $(TARGET) srop.o

.PHONY: all clean
