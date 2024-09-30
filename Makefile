CC := gcc
LDFLAGS := -lssl -lcrypto
SQLITE_LDFLAGS := -lsqlite3
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all: enc-client enc-server

enc-client: enc-client.o
	$(CC) $(CFLAGS) -o enc-client enc-client.o $(LDFLAGS)

enc-client.o: enc-client.c
	$(CC) $(CFLAGS) -c enc-client.c

enc-server: enc-server.o
	$(CC) $(CFLAGS) -o enc-server enc-server.o $(LDFLAGS) $(SQLITE_LDFLAGS)

enc-server.o: enc-server.c
	$(CC) $(CFLAGS) -c enc-server.c

clean:
	rm -f enc-server enc-server.o enc-client enc-client.o
