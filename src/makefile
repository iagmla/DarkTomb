CC=gcc
CFLAGS=-O3 -std=c99 -w
TARGET=tomb
all: $(TARGET)

$(TARGET): tomb.c
	$(CC) tomb.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
