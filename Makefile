CC=clang
CFLAGS= -O2 -c -pipe -Wall -Wno-unused-function -std=c99

LDFLAGS= -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto

all: reimagine

reimagine: main.o helper.o opensn0w-X/src/image3.o opensn0w-X/src/util.o opensn0w-X/src/ibootsup.o opensn0w-X/src/patch.o
	$(CC) $(LDFLAGS) helper.o main.o opensn0w-X/src/image3.o opensn0w-X/src/util.o opensn0w-X/src/ibootsup.o opensn0w-X/src/patch.o -o reimagine

main.o: main.c
	$(CC) $(CFLAGS) main.c

helper.o: helper.c
	$(CC) $(CFLAGS) helper.c

clean:
	rm *o reimagine

