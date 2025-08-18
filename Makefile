CC = gcc
CFLAGS = -Wall -Wextra -I./src
LDFLAGS = -lssl -lcrypto -lcurl

SRCS = src/main.c src/hash_utils.c src/hdb_parser.c src/quarantine.c src/update_database.c
OBJS = $(SRCS:.c=.o)

all: viscan

viscan: $(OBJS)
	$(CC) -o viscan $(OBJS) $(LDFLAGS)

src/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f src/*.o viscan
