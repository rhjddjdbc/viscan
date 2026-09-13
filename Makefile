<LeftMouse>CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Isrc/h
LDLIBS   = -lcurl -lcrypto

SRCDIR   = src
SRCS     = $(SRCDIR)/main.c \
           $(SRCDIR)/hash_utils.c \
           $(SRCDIR)/hdb_parser.c \
           $(SRCDIR)/quarantine.c \
           $(SRCDIR)/update_database.c \
           $(SRCDIR)/ac_engine.c
OBJS     = $(SRCS:.c=.o)

.PHONY: all clean
all: viscan

viscan: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) viscan
