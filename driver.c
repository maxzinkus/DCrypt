/* Max Zinkus
 * CPE 323 Lab 4
 * Winter 2017
 * driver.c
 */

#include <stdio.h>
#include <string.h>

#include "dcrypt.h"

int main(int argc, char **argv) {
   disk_label id[MAX_FILES] = {0};
   status_code status;
   char b1[100] = {0}, b2[100] = {0};

   char *fmt = "disk%d.d";
   char *fmtt = "data%d.ad";

   for (int i = 0; i < MAX_FILES + 10; i++) {
      snprintf(b1, 100, fmt, i);
      snprintf(b2, 100, fmtt, i);
      status = createDisk(b1, b2, BLOCKSIZE);
      if (status == SUCCESS) {
         status = mountDiskHelper(b1, b2, id+i, PERM_READ);
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
