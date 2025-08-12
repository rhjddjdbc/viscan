CC = gcc
CFLAGS = -Wall -Wextra -I./src -lssl -lcrypto

OBJS = src/main.o src/hash_utils.o src/hdb_parser.o src/quarantine.o

all: viscan

viscan: $(OBJS)
	$(CC) -o viscan $(OBJS) $(CFLAGS)

src/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f src/*.o viscan

