CFLAGS=-Wall -Werror -Wpedantic -Wshadow -std=c99

driver: driver.c libdcrypt.a
	gcc -g -std=c99 -lsodium -L. -ldcrypt -o $@ $<

libdcrypt.a: dcrypt.c dcrypt.h
	gcc -flto $(CFLAGS) -O3 -Os -fPIC -shared -o $@ $<

clean:
	$(RM) driver libdcrypt.a
wipe:
	$(RM) disks/*.d disks/*.ad
