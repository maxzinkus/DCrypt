/* Max Zinkus
 * dcrypt.h
 */

#include <sodium.h>
#include <stdint.h>

#define BLOCKSIZE 4096
#define KEYSIZE 32
#define TAGSIZE 16
#define MACSIZE crypto_auth_hmacsha512_BYTES
#define GCMNONCESIZE 12
#define SALSANONCESIZE 24
#define SALTSIZE crypto_pwhash_scryptsalsa208sha256_SALTBYTES
/* size of whole AD header */
#define HEADERSIZE (SALSANONCESIZE + SALTSIZE + KEYSIZE + MACSIZE)
/* size of each AD within the AD header */
#define ADSIZE (GCMNONCESIZE + TAGSIZE)

#define MAX_SIZE 268435456       /* max 256Mb disks : CHANGEME       */
#define MAX_FILES INT8_MAX       /* max 128 mounted disks : CHANGEME */
#define MAX_FILENAME 256         /* max path length                  */
#define MAX_KEK 256
#define KEKMSG "Input password (<256 characters):\n"
#define KEKERR "Error collecting password.\n"
#define KEKSHORT "Error: password too short.\n"

typedef enum {
   SUCCESS,
   ENOTMOUNTED,
   EMISALIGNED,
   ELIMIT,
   EMODE,
   ESIZE,
   EDENY,
   ECLOSE,
   EOPEN,
   EUNLINK,
   ESEEK,
   EWRITE,
   EREAD,
   EALLOC,
   ETRUNC,
   ESTAT,
   EEXISTS,
   EACCESS,
   ECRYPT,
} status_code;

#define PERM_READ 0x0f
#define PERM_WRITE 0xf0

typedef int8_t disk_label;
typedef uint8_t mt_perm;

typedef enum {WIPE_FAST, WIPE_DOE_SECURE, WIPE_DOD_SECURE} wipe_mode;

/* managing encryption during disk mount */
typedef struct {
   int adfd;
   uint8_t *dek;
} crypt_info;

/* live data structure for disk use */
typedef struct {
   char *filename;
   mt_perm perm;
   int fd;
   uint32_t nblocks;
   uint64_t size;
   crypt_info *crypt;
} disk_info;

/* mount file-based disk */
status_code mountDiskHelper(const char *file,
                            const char *adfile,
                            disk_label *id,
                            mt_perm perm);

/* mount disk: set up data structures */
status_code mountDisk(const int fd,
                      const int adfd,
                      disk_label *id,
                      mt_perm perm);

/* unmount disk: free data structures, clean close */
status_code unmountDisk(const disk_label id);

/* seek a disk to an offset for a given block */
status_code seekDisk(const disk_label id, const uint32_t block);

/* read data to buffer from block #block in disk id */
status_code readBlock(const disk_label id, const uint32_t block, void *buffer);

/* write data in buffer to block #block in disk id */
status_code writeBlock(const disk_label id, const uint32_t block, void *buffer);

/* create disk file */
status_code createDisk(const char *file, const char *adfile, const uint64_t size);

/* wipe disk: fast writes 0s, secure writes garbage in multiple passes */
status_code wipeDisk(const disk_label id, wipe_mode mode);

/* resize disk to size*/
status_code truncateDisk(const disk_label id, const uint64_t size);

/* check status_code and print errors */
void check(status_code status);
