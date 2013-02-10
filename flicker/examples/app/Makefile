CFLAGS := -g -I../pal -I../../pal
LDFLAGS := -g

all: noio rlimit bcflick.a

params.o: ../../pal/params.c
	$(CC) -c $< -o $@

noio: noio.o callpal.o
	$(CC) -o $@ $^ $(LDFLAGS)

rlimit: rlimit.o callpal.o params.o
	$(CC) -o $@ $^ $(LDFLAGS)

bcflick.a: bcflick.o callpal.o params.o
	$(AR) rcs $@ $^

