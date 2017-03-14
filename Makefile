CFLAGS=-Wall -Werror -Wpedantic -std=c99

driver: driver.c libdcrypt.a
	gcc -g -std=c99 -lsodium -L. -ldcrypt -o driver driver.c

libdcrypt.a: dcrypt.c dcrypt.h
	gcc -g $(CFLAGS) -fPIC -shared -o libdcrypt.a dcrypt.c

clean:
	rm driver libdcrypt.a
wipe:
	rm *.d *.ad
