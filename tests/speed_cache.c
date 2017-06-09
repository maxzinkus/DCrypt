#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../dcrypt.h"

#define BIG 16384

int main(int argc, char **argv) {
   disk_label id;
   status_code status;
   char b[BLOCKSIZE];

   for (int i = 0; i < BLOCKSIZE; i++) {
      b[i] = i;
   }

   char *d = "disks/cache_disk.d";
   char *ad = "disks/cache_disk.ad";

   status = createDisk(d, ad, BIG*BLOCKSIZE);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }

   status = mountDiskHelper(d, ad, &id, PERM_READ | PERM_WRITE, false);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }

   for (int i = 0; i < BIG; i++) {
      status = writeBlock(id, i, b);
      if (status != SUCCESS) {
         check(status);
         return 1;
      }
   }
   
   for (int i = BIG-1; i >= 0; i--) {
      status = readBlock(id, i, b);
      if (status != SUCCESS) {
         check(status);
         return 1;
      }
   }
   
   status = unmountDisk(id);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }
   return 0; 
}
