#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../dcrypt.h"

int main(int argc, char **argv) {
   disk_label id;
   status_code status;
   char b[2*BLOCKSIZE];

   for (int i = 0; i < 2*BLOCKSIZE; i++) {
      b[i] = i;
   }

   char *d = "disks/cache_disk.d";
   char *ad = "disks/cache_disk.ad";

   status = createDisk(d, ad, 2*BLOCKSIZE);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }

   status = mountDiskHelper(d, ad, &id, PERM_READ | PERM_WRITE, true);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }
   
   status = writeBlock(id, 0, b);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }
   status = readBlock(id, 0, b);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }

   fprintf(stderr, "1\n");
   status = writeBlock(id, 1, b);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }
   fprintf(stderr, "2\n");
   status = readBlock(id, 1, b);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }

   fprintf(stderr, "3\n");
   status = unmountDisk(id);
   if (status != SUCCESS) {
      check(status);
      return 1;
   }
   return 0; 
}
