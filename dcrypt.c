/* Max Zinkus
 * dcrypt.c
 */

#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "dcrypt.h"

#define ABS(x) ((x) < 0) ? (-(x)) : (x)

static int8_t CRYPT_INIT = 0;
static int8_t NUM_OPEN = 0;
static disk_info *OPENED[MAX_FILES] = {0};

// allocate space for disk_info and crypt_info and init size fields
status_code allocDiskInfo(const disk_label id, const int fd);

/* given an AD file descriptor, authenticate the header,
 * decrypt, and write the disk encryption key to the caller
 */
status_code mountDiskCryptInit(const int adfd,
                               uint8_t * const dek,
                               const uint32_t nblocks);

// write out and encrypt the AD file structures and authentication data
status_code unmountDiskCryptFinalize(const disk_label id);

status_code mountDisk(const int fd,
                      const int adfd,
                      disk_label *id,
                      const mt_perm perm) {
   status_code status;
   *id = -1;
   if (!CRYPT_INIT) {
      // init libsodium if it hasn't happened yet
      if (sodium_init() == -1) {
         return ECRYPT;
      }
      CRYPT_INIT = 1;
   }
   if (NUM_OPEN == MAX_FILES) {
      return ELIMIT; // no room in OPENED table
   }
   NUM_OPEN++;
   int8_t spot = (fd - 3) % MAX_FILES;
   while (OPENED[spot]) {
      spot = (spot + 1) % MAX_FILES;
   }

   // allocate space and initialize size fields
   status = allocDiskInfo(spot, fd);
   if (status != SUCCESS) {
      free((OPENED[spot])->crypt);
      free(OPENED[spot]);
      OPENED[spot] = NULL;
      NUM_OPEN--;
      return status;
   }
 
   // save FDs and permission to disk_info
   (OPENED[spot])->fd = fd;
   (OPENED[spot])->perm = perm;
   ((OPENED[spot])->crypt)->adfd = adfd;

   // get AD size to determine if it's new
   struct stat adst = {0};
   int stat_result = fstat(adfd, &adst);
   if (stat_result < 0) {
      free((OPENED[spot])->crypt);
      free(OPENED[spot]);
      OPENED[spot] = NULL;
      NUM_OPEN--;
      return ESTAT;
   }

   // create protected space for data encryption key and E(dek) from AD file
   ((OPENED[spot])->crypt)->dek = sodium_malloc(KEYSIZE);
   uint8_t *dek = sodium_malloc(KEYSIZE);

   if (adst.st_size > 0) { // if the ad file was previously created
      /* perform AD file header authentication and decryption
       * with the ultimate goal of loading the dek into *dek
       */
      status = mountDiskCryptInit(((OPENED[spot])->crypt)->adfd,
                                    dek, (OPENED[spot])->nblocks);
      if (status != SUCCESS) {
         free((OPENED[spot])->crypt);
         free(OPENED[spot]);
         OPENED[spot] = NULL;
         NUM_OPEN--;
         return status;
      }
   }
   else if (adst.st_size == 0) { // if the ad file was just created
      /* zero the AD file to size of header so that it will either be
       * init'd successfully or cause terminating errors
       */
      int truncate_result = ftruncate(((OPENED[spot])->crypt)->adfd, HEADERSIZE);
      if (truncate_result < 0) {
         sodium_free(((OPENED[spot])->crypt)->dek);
         free((OPENED[spot])->crypt);
         free(OPENED[spot]);
         OPENED[spot] = NULL;
         NUM_OPEN--;
         return ETRUNC;
      }
 
      // create new random data encryption key, E(dek) will be saved later
      randombytes_buf(dek, KEYSIZE);
   }
   else {
      // adst.st_size was not 0 or larger?
      free((OPENED[spot])->crypt);
      free(OPENED[spot]);
      OPENED[spot] = NULL;
      NUM_OPEN--;
      return ESTAT;
   }

   // move dek into crypt_info
   memcpy(((OPENED[spot])->crypt)->dek, dek, KEYSIZE);
   sodium_free(dek);

   // key shouldn't be modified
   sodium_mprotect_readonly(((OPENED[spot])->crypt)->dek);

   *id = spot; // send the caller the disk_label
   return SUCCESS;
}

status_code unmountDisk(const disk_label id) {
   status_code status = SUCCESS;
   if (!OPENED[id]) {
      return status; // idempotent
   }

   // encrypt and save dek along with authentication data and nonces to AD file
   status = unmountDiskCryptFinalize(id);
   if (status != SUCCESS) {
      sodium_free(((OPENED[id])->crypt)->dek);
      free((OPENED[id])->crypt);
      free(OPENED[id]);
      OPENED[id] = NULL;
      return status;
   }
 
   // zero and free protected memory, and zero pointers
   sodium_free(((OPENED[id])->crypt)->dek);
   ((OPENED[id])->crypt)->dek = NULL;

   // close various descriptors
   int close_result = close((OPENED[id])->fd);
   if (close_result < 0) {
      status |= ECLOSE;
   }
   close_result = close(((OPENED[id])->crypt)->adfd);
   if (close_result < 0) {
      status |= ECLOSE;
   }

   // clean up non-protected heap structures
   // crypt_info
   free((OPENED[id])->crypt); 
   (OPENED[id])->crypt = NULL;
   // disk_info
   free(OPENED[id]);

   // make OPENED table spot available
   OPENED[id] = NULL;
   NUM_OPEN--;
   // return success or inform of possible crypto AND possible file errors
   return status;
}

status_code seekDisk(const disk_label id,
                     const uint32_t block) {
   uint64_t offset;
   if (!OPENED[id]) {
      return ENOTMOUNTED;
   }
   if (block >= (OPENED[id])->nblocks) {
      return EMISALIGNED; // must seek to the beginning of a block
   }
   // calculate file offset and lseek
   offset = block*BLOCKSIZE;
   off_t seek_result = lseek((OPENED[id])->fd, offset, SEEK_SET);
   if (seek_result == (off_t)-1) {
      return ESEEK;
   }
   // seek AD file descriptor assuming data will be read
   offset = HEADERSIZE + block*ADSIZE;
   seek_result = lseek(((OPENED[id])->crypt)->adfd, offset, SEEK_SET);
   if (seek_result == (off_t)-1) {
      return ESEEK;
   }
   return SUCCESS;
}

status_code readBlock(const disk_label id,
                      const uint32_t block,
                      void *buffer) {
   if (!OPENED[id]) {
      return ENOTMOUNTED;
   }
   if (!((OPENED[id])->perm & PERM_READ)) {
      return EDENY; // not mounted as readable
   }
   if (block >= (OPENED[id])->nblocks) {
      return ESIZE; // don't read past end
   }

   status_code status = seekDisk(id, block);
   if (status != SUCCESS) {
      return status;
   }
   int crypt_result = -1;
   ssize_t read_result;
   uint8_t nonce[GCMNONCESIZE] = {0}, tag[TAGSIZE] = {0};
   uint8_t *crypt, *plain;

   plain = calloc(BLOCKSIZE, 1);
   if (!plain) {
      return EALLOC;
   }
   crypt = calloc(BLOCKSIZE, 1);
   if (!crypt) {
      free(plain);
      return EALLOC;
   }

   read_result = read((OPENED[id])->fd, crypt, BLOCKSIZE);
   if (read_result < 0) {
      free(crypt);
      free(plain);
      return EREAD;
   }
   read_result = read(((OPENED[id])->crypt)->adfd, nonce, GCMNONCESIZE);
   if (read_result < 0) {
      free(crypt);
      free(plain);
      return EREAD;
   }
   read_result = read(((OPENED[id])->crypt)->adfd, tag, TAGSIZE);
   if (read_result < 0) {
      free(crypt);
      free(plain);
      return EREAD;
   }
   crypt_result = crypto_aead_aes256gcm_decrypt_detached(plain, NULL, crypt,
                                           BLOCKSIZE, tag, NULL, 0, nonce,
                                           ((OPENED[id])->crypt)->dek);
   if (crypt_result < 0) {
      free(crypt);
      free(plain);
      return ECRYPT;
   }

   memcpy(buffer, plain, BLOCKSIZE);
   free(crypt);
   free(plain);
   return SUCCESS;
}

status_code writeBlock(const disk_label id,
                       const uint32_t block,
                       void *buffer) {
   if (!OPENED[id]) {
      return ENOTMOUNTED;
   }
   if (!((OPENED[id])->perm & PERM_WRITE)) {
      return EDENY; // not mounted as writeable
   }
   if (block >= (OPENED[id])->nblocks) {
      return ESIZE; // don't write past end
   }
   status_code status = seekDisk(id, block);
   if (status != SUCCESS) {
      return status;
   }
   ssize_t read_result, write_result;
   uint8_t nonce[GCMNONCESIZE] = {0}, tag[TAGSIZE] = {0}, *crypt = NULL;

   crypt = calloc(BLOCKSIZE, 1);
   if (!crypt) {
      return EALLOC;
   }
   
   read_result = read(((OPENED[id])->crypt)->adfd, nonce, GCMNONCESIZE);
   if (read_result < 0) {
      free(crypt);
      return EREAD;
   }
   
   sodium_increment(nonce, GCMNONCESIZE);
   
   crypto_aead_aes256gcm_encrypt_detached(crypt, tag, NULL, buffer,
                                           BLOCKSIZE, NULL, 0, NULL,
                                           nonce, ((OPENED[id])->crypt)->dek);
   status = seekDisk(id, block);
   if (status != SUCCESS) {
      return status;
   }
   write_result = write((OPENED[id])->fd, crypt, BLOCKSIZE);
   if (write_result < 0) {
      free(crypt);
      return EWRITE;
   }
   write_result = write(((OPENED[id])->crypt)->adfd, nonce, GCMNONCESIZE);
   if (write_result < 0) {
      free(crypt);
      return EWRITE;
   }
   write_result = write(((OPENED[id])->crypt)->adfd, tag, TAGSIZE);
   if (write_result < 0) {
      free(crypt);
      return EWRITE;
   }

   free(crypt);
   return SUCCESS;
}

status_code createDisk(const char *file,
                       const char *adfile,
                       const uint64_t size) {
   if (size % BLOCKSIZE) {
      return EMISALIGNED;
   }
   int access_result = access(file, F_OK);
   if (!access_result) {
      return EEXISTS; // refuse to treat existing files as new block devices
   }
   access_result = access(adfile, F_OK);
   if (!access_result) {
      return EEXISTS; // refuse to treat existing files as a new AD files
   }
   int fd = open(file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
   if (fd < 0) {
      return EOPEN;
   }

   int adfd = open(adfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
   if (adfd < 0) {
      return EOPEN;
   }

   // resize file to size
   int truncate_result = ftruncate(fd, size);
   if (truncate_result < 0) {
      return ETRUNC;
   }
 
   // close fds
   fd = close(fd);
   if (fd < 0) {
      return ECLOSE;
   }
   adfd = close(adfd);
   if (adfd < 0) {
      return ECLOSE;
   }
   return SUCCESS;
}

status_code truncateDisk(const disk_label id,
                         const uint64_t size) {
   if (!OPENED[id]) {
      return ENOTMOUNTED;
   }
   if (size > MAX_SIZE) {
      return ESIZE;
   }
   if (size % BLOCKSIZE) {
      return EMISALIGNED; // must remain aligned
   }
   if (!(size - (OPENED[id])->size)) {
      return SUCCESS; // if size change is 0, we're done
   }
   
   int truncate_result = ftruncate((OPENED[id])->fd, size);
   if (truncate_result < 0) {
      return ETRUNC;
   }
   truncate_result = ftruncate(((OPENED[id])->crypt)->adfd,
                                 HEADERSIZE + ADSIZE * (size / BLOCKSIZE));
   if (truncate_result < 0) {
      return ETRUNC;
   }
   // update size fields
   (OPENED[id])->size = size;
   (OPENED[id])->nblocks = size / BLOCKSIZE;
   
   return SUCCESS;
}

status_code wipeDisk(const disk_label id,
                     wipe_mode mode) {
   status_code status = 0;
   if (!OPENED[id]) {
      return ENOTMOUNTED;
   }
   if (!((OPENED[id])->perm & PERM_WRITE)) {
      return EDENY; // don't wipe if not writeable
   }
   char *buffer = malloc(BLOCKSIZE);
   if (!buffer) {
      return EALLOC;
   }
   switch (mode) {
      // don't run this on an SSD please
      case WIPE_DOD_SECURE:
         memset(buffer, 0x35, BLOCKSIZE);
         for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
            status |= writeBlock(id, i, buffer);
         }
         memset(buffer, 0xCB, BLOCKSIZE);
         for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
            status |= writeBlock(id, i, buffer);
         }
         randombytes_buf(buffer, BLOCKSIZE);
         for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
            status |= writeBlock(id, i, buffer);
         }
      case WIPE_DOE_SECURE:
         randombytes_buf(buffer, BLOCKSIZE);
         for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
            status |= writeBlock(id, i, buffer);
         }
         memset(buffer, 0, BLOCKSIZE);
         for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
            status |= writeBlock(id, i, buffer);
         }
         memset(buffer, 1, BLOCKSIZE);
         for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
            status |= writeBlock(id, i, buffer);
         }
      case WIPE_FAST:
         memset(buffer, 0, BLOCKSIZE);
         for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
            status |= writeBlock(id, i, buffer);
         }
         if (status != SUCCESS) {
            return status;
         }
         break;
      default:
         free(buffer);
         return EMODE;
   }
   free(buffer);
   return SUCCESS;
}

status_code mountDiskHelper(const char *file,
                            const char *adfile,
                            disk_label *id,
                            const mt_perm perm) {
   int fd, adfd;

   // access check
   int access_mode = 0, access_result;
   if (perm & PERM_READ) {
      access_mode |= R_OK;
   }
   if (perm & PERM_WRITE) {
      access_mode |= W_OK;
   }
   if (!access_mode) {
      return EACCESS;
   }
   access_result = access(file, access_mode);
   if (access_result < 0) {
      return EACCESS;
   }
   access_result = access(adfile, access_mode);
   if (access_result < 0) {
      return EACCESS;
   }
   // open the requested file to be used as a block device with given perms
   mode_t open_mode = 0;
   if (perm & (PERM_READ|PERM_WRITE)) {
      open_mode = O_RDWR;
   }
   else if (perm & PERM_WRITE) {
      open_mode = O_WRONLY;
   }
   else if (perm & PERM_READ) {
      open_mode = O_RDONLY;
   }
   else {
      return EOPEN;
   }
   fd = open(file, open_mode);
   if (fd < 0) {
      return EOPEN;
   }
   // open associated data file descriptor
   adfd = open(adfile, open_mode);
   if (adfd < 0) {
      return EOPEN;
   }
   return mountDisk(fd, adfd, id, perm);
}

status_code allocDiskInfo(const disk_label id,
                          const int fd) {
   // alloc space for disk_info
   OPENED[id] = calloc(sizeof(disk_info), 1);
   if (!OPENED[id]) {
      return EALLOC;
   }

   (OPENED[id])->crypt = calloc(sizeof(crypt_info), 1);
   if (!((OPENED[id])->crypt)) {
      return EALLOC;
   }

   // get size and nblocks
   struct stat st = {0};
   int stat_result = fstat(fd, &st);
   if (stat_result < 0) {
      free((OPENED[id])->crypt);
      return ESTAT;
   }
   if (st.st_size % BLOCKSIZE) {
      free((OPENED[id])->crypt);
      return EMISALIGNED;
   }
   (OPENED[id])->size = st.st_size;
   (OPENED[id])->nblocks = st.st_size / BLOCKSIZE;
   return SUCCESS;
}

uint8_t *getKek() {
   uint8_t *kek, *kek_buf = sodium_malloc(MAX_KEK);
   ssize_t write_result = write(1, KEKMSG, strlen(KEKMSG));
   if (write_result < 0) {
      return NULL;
   }

   kek_buf = (uint8_t *)fgets((char *)kek_buf, MAX_KEK, stdin);
   if (!kek_buf) {
      write(1, KEKERR, strlen(KEKERR));
      return NULL; // Error taking input
   }
   size_t len = strnlen((char *)kek_buf, MAX_KEK);

   kek = sodium_malloc(len);
   memcpy(kek, kek_buf, len);
   kek[len-1] = '\0';
   sodium_free(kek_buf);

   return kek; // caller must sodium_free
}

status_code mountDiskCryptInit(const int adfd,
                               uint8_t * const dek,
                               const uint32_t nblocks) {
   uint8_t *kek;
   uint8_t header_auth[HEADERSIZE-MACSIZE] = {0}, block_auth[ADSIZE] = {0};
   uint8_t nonce[SALSANONCESIZE] = {0}, enckey[KEYSIZE] = {0}, *kdfkey;
   uint8_t *authkey, *cryptkey, hmac[MACSIZE] = {0}, salt[SALTSIZE] = {0};
   size_t keklen;
   ssize_t read_result;
   off_t lseek_result;
   int verify = -1, crypt_result, scrypt_result;
 
   lseek_result = lseek(adfd, 0, SEEK_SET);
   if (lseek_result == (off_t)-1) {
      return ESEEK;
   }

   // read nonce, authsalt, cryptsalt, E(dek), and hmac from AD file
   read_result = read(adfd, nonce, SALSANONCESIZE);
   if (read_result < 0) {
      return EREAD;
   }
   read_result = read(adfd, salt, SALTSIZE);
   if (read_result < 0) {
      return EREAD;
   }
   read_result = read(adfd, enckey, KEYSIZE);
   if (read_result < 0) {
      return EREAD;
   }
   read_result = read(adfd, hmac, MACSIZE);
   if (read_result < 0) {
      return EREAD;
   }

   // get key-encryption key from user
   kek = getKek();
   if (!kek) {
      fprintf(stderr, "key input failed while mounting device\n");
      return ECRYPT;
   }

   keklen = strnlen((char *)kek, MAX_KEK);

   kdfkey = sodium_malloc(2*KEYSIZE);

   // derive authkey and cryptkey
   scrypt_result = crypto_pwhash_scryptsalsa208sha256(kdfkey,
                                    2*KEYSIZE,
                                    (char *)kek,
                                    keklen,
                                    salt,
                  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
   if (scrypt_result < 0) {
      sodium_free(kek);
      sodium_free(kdfkey);
      return ECRYPT;
   }
   sodium_free(kek);

   authkey = sodium_malloc(KEYSIZE);
   cryptkey = sodium_malloc(KEYSIZE);

   memcpy(cryptkey, kdfkey, KEYSIZE);
   memcpy(authkey, kdfkey + KEYSIZE, KEYSIZE);

   sodium_free(kdfkey);
   
   // generate our hmac and verify
   memcpy(header_auth, nonce, SALSANONCESIZE);
   memcpy(header_auth + SALSANONCESIZE, salt, SALTSIZE);
   memcpy(header_auth + SALSANONCESIZE + SALTSIZE, enckey, KEYSIZE);

   unsigned char hash[MACSIZE] = {0};
   crypto_auth_hmacsha512_state state;

   crypto_auth_hmacsha512_init(&state, authkey, KEYSIZE);

   crypto_auth_hmacsha512_update(&state, header_auth, HEADERSIZE - MACSIZE);

   for (uint32_t i = 0; i < nblocks; i++) {
      read_result = read(adfd, block_auth, ADSIZE);
      if (read_result < 0) {
         sodium_free(cryptkey);
         sodium_free(authkey);
         return EREAD;
      }
      crypto_auth_hmacsha512_update(&state, block_auth, ADSIZE);
   }

   crypto_auth_hmacsha512_final(&state, hash);

   sodium_free(authkey);

   verify = sodium_memcmp(hmac, hash, MACSIZE);

   if (verify < 0) {
      fprintf(stderr, "failed to verify device!\n");
      sodium_free(cryptkey);
      return ECRYPT;
   }
 
   // decrypt dek
   crypt_result = crypto_stream_xor(dek, enckey, KEYSIZE, nonce, cryptkey);
   if (crypt_result < 0) {
      sodium_free(cryptkey);
      return ECRYPT;
   }
   sodium_free(cryptkey);
   return SUCCESS;
}

status_code unmountDiskCryptFinalize(const disk_label id) {
   uint8_t *kek, *dek;
   uint8_t nonce[SALSANONCESIZE] = {0}, salt[SALTSIZE] = {0};
   uint8_t *kdfkey, *authkey, *cryptkey;
   uint8_t header_auth[HEADERSIZE-MACSIZE] = {0}, block_auth[ADSIZE] = {0};
   size_t keklen;
   int scrypt_result, crypt_result;

   // randomize nonce and salt
   randombytes_buf(nonce, SALSANONCESIZE);
   randombytes_buf(salt, SALTSIZE);

   // get key encryption key from user
   kek = getKek();
   if (!kek) {
      fprintf(stderr, "key input failed while unmounting device\n");
      return ECRYPT;
   }

   keklen = strnlen((char *)kek, MAX_KEK);

   dek = sodium_malloc(KEYSIZE);
   kdfkey = sodium_malloc(2*KEYSIZE);
 
   // derive cryptkey and authkey
   scrypt_result = crypto_pwhash_scryptsalsa208sha256(kdfkey,
                                    2*KEYSIZE,
                                    (char *)kek,
                                    keklen,
                                    salt,
                  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
   if (scrypt_result < 0) {
      sodium_free(kek);
      sodium_free(dek);
      sodium_free(kdfkey);
      return ECRYPT;
   }
   sodium_free(kek);

   cryptkey = sodium_malloc(KEYSIZE);
   authkey = sodium_malloc(KEYSIZE);

   memcpy(cryptkey, kdfkey, KEYSIZE);
   memcpy(authkey, kdfkey + KEYSIZE, KEYSIZE);

   sodium_free(kdfkey);
 
   // encrypt crypt_info->dek with nonce, cryptkey into dek
   crypt_result = crypto_stream_xor(dek, ((OPENED[id])->crypt)->dek,
                                        KEYSIZE, nonce, cryptkey);
   if (crypt_result < 0) {
      sodium_free(dek);
      sodium_free(cryptkey);
      sodium_free(authkey);
      return ECRYPT;
   }
   sodium_free(cryptkey);
 
   // generate our hmac
   memcpy(header_auth, nonce, SALSANONCESIZE);
   memcpy(header_auth + SALSANONCESIZE, salt, SALTSIZE);
   memcpy(header_auth + SALSANONCESIZE + SALTSIZE, dek, KEYSIZE);
   
   unsigned char hash[MACSIZE] = {0};
   crypto_auth_hmacsha512_state state;

   crypto_auth_hmacsha512_init(&state, authkey, KEYSIZE);

   crypto_auth_hmacsha512_update(&state, header_auth, HEADERSIZE - MACSIZE);

   off_t lseek_result = lseek(((OPENED[id])->crypt)->adfd, HEADERSIZE, SEEK_SET);
   if (lseek_result == (off_t)-1) {
      sodium_free(dek);
      sodium_free(authkey);
      return ESEEK;
   }

   ssize_t read_result;
   for (uint32_t i = 0; i < (OPENED[id])->nblocks; i++) {
      read_result = read(((OPENED[id])->crypt)->adfd, block_auth, ADSIZE);
      if (read_result < 0) {
         sodium_free(dek);
         sodium_free(authkey);
         return EREAD;
      }
      crypto_auth_hmacsha512_update(&state, block_auth, ADSIZE);
   }

   crypto_auth_hmacsha512_final(&state, hash);

   sodium_free(authkey);

   lseek_result = lseek(((OPENED[id])->crypt)->adfd, 0, SEEK_SET);
   if (lseek_result == (off_t)-1) {
      sodium_free(dek);
      return ESEEK;
   }

   // write nonce, salt, E(dek), hmac to AD file
   ssize_t write_result = write(((OPENED[id])->crypt)->adfd, nonce, SALSANONCESIZE);
   if (write_result < 0) {
      sodium_free(dek);
      return EWRITE;
   }
   write_result = write(((OPENED[id])->crypt)->adfd, salt, SALTSIZE);
   if (write_result < 0) {
      sodium_free(dek);
      return EWRITE;
   }
   write_result = write(((OPENED[id])->crypt)->adfd, dek, KEYSIZE);
   if (write_result < 0) {
      sodium_free(dek);
      return EWRITE;
   }
   sodium_free(dek);
   write_result = write(((OPENED[id])->crypt)->adfd, hash, MACSIZE);
   if (write_result < 0) {
      return EWRITE;
   }

   return SUCCESS;
}

void check(status_code status) {
   if (status & ECRYPT) {
      fprintf(stderr, "integrity failure or cryptography error\n");
   }
   if (status & EACCESS) {
      fprintf(stderr, "access denied or access error\n");
   }
   if (status & EEXISTS) {
      fprintf(stderr, "file exists, refusing to overwrite\n");
   }
   if (status & ESTAT) {
      fprintf(stderr, "stat error\n");
   }
   if (status & ETRUNC) {
      fprintf(stderr, "truncate error\n");
   }
   if (status & EALLOC) {
      fprintf(stderr, "allocation error\n"); 
   }
   if (status & EREAD) {
      fprintf(stderr, "read error\n"); 
   }
   if (status & EWRITE) {
      fprintf(stderr, "write error\n"); 
   }
   if (status & ESEEK) {
      fprintf(stderr, "seek error\n"); 
   }
   if (status & EUNLINK) {
      fprintf(stderr, "unlink error\n"); 
   }
   if (status & EOPEN) {
      fprintf(stderr, "open error\n"); 
   }
   if (status & ECLOSE) {
      fprintf(stderr, "close error\n"); 
   }
   if (status & EDENY) {
      fprintf(stderr, "permission denied\n"); 
   }
   if (status & ESIZE) {
      fprintf(stderr, "access past end of device\n"); 
   }
   if (status & EMODE) {
      fprintf(stderr, "bad mode given\n"); 
   }
   if (status & ELIMIT) {
      fprintf(stderr, "reached limit of open disks\n"); 
   }
   if (status & EMISALIGNED) {
      fprintf(stderr, "value not blocksize-aligned\n"); 
   }
   if (status & ENOTMOUNTED) {
      fprintf(stderr, "disk is not mounted\n"); 
   }
}
