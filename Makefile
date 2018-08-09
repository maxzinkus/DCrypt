CC=clang
CFLAGS=-Wall -Werror -Wpedantic -Wshadow -std=gnu11 -flto -O3

%.o: %.c libdcrypt.a
	$(CC) $(CFLAGS) -std=c11 -lsodium -L. -ldcrypt -o $@ $<

libdcrypt.a: dcrypt.c dcrypt.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

clean:
	$(RM) driver libdcrypt.a
wipe:
	$(RM) disks/*.d disks/*.ad
