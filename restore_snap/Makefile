TARGET = restore_snap

CC = gcc
CFLAGS = -Wall -Wextra -O2

SRC = $(TARGET).c

BIN = $(TARGET)

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

clean:
	rm -f $(BIN)

.PHONY: all clean
