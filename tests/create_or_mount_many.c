#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../dcrypt.h"

int main(int argc, char **argv) {
   disk_label id[MAX_FILES] = {0};
   status_code status;
   char b1[100] = {0}, b2[100] = {0};

   char *fmt = "disks/disk%d.d";
   char *fmtt = "disks/data%d.ad";

   for (int i = 0; i < MAX_FILES; i++) {
      snprintf(b1, 100, fmt, i);
      snprintf(b2, 100, fmtt, i);
      if (access(b1, F_OK) != -1) {
         status = SUCCESS;
      }
      else {
         status = createDisk(b1, b2, BLOCKSIZE);
      }
      if (status == SUCCESS) {
         status = mountDiskHelper(b1, b2, id+i, PERM_READ, false);
         check(status);
      }
      else {
         check(status);
      }
   }

   for (int i = 0; i < MAX_FILES; i++) {
      unmountDisk(id[i]);
   }

   return 0;
}
