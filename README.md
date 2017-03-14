DCrypt: Disk Cryptography
=========================

Block device encryption (simulator)
-----------------------------------

We use an associated data file intended to be stored separately from the
encrypted device by the user, mounted and accessed at mount of the encrypted
device and required during device use.

For the associated data, `HEADERSIZE + numblocks * ADSIZE` bytes are required.
For example, with a full 16 Tb device, 112 Gb + a small header are needed in
order to utilize randomized, authenticated encryption for the device.

```
ADSIZE / 16 Tb = (NONCESIZE + TAGSIZE) / BLOCKSIZE
x / (16 * 2**40) == (12 + 16) / 4096
x / 2**44 == 28 / 4096
x == (28 / 2**12) * 2**44
x == 120259084288
x / 2**30 == 112
```

Security assumptions
--------------------
1. Protect the AD file with your life (see below)
2. Change your password often for best results (see below)
3. Data should be migrated to a new disk after many re-encryptions per GCM use
4. The hardware and kernel/hypervisor must support Intel VT-d or AMD IOMMU

AD file security
----------------
If an adversary can modify your AD file, your data is safe because they'll
have to break XSalsa20 with a random 192-bit nonce and a password of your
choice of 16 or more characters, run through scrypt with a random salt.

However, they can
1. Invalidate your disk entirely
2. Prevent you from ever decrypting again
3. Trick you into re-using nonces, thereby allowing them to *forge blocks*

In order to achieve #3, the adversary would have to either
1. Modify an IV then let you to write over a block without decrypting it
2. Modify an IV while the disk is mounted then let you write over the block

Assuming use of an external USB to host associated data, when plugging in the
external device, the VT-d (or IOMMU)-enabled kernel must be expecting such a
device, and reserve the USB controller for use by the device-operating process
or domain only.

With processor-supported device IO protections and an initial authentication
of the whole AD file, these attacks are vastly mitigated, the remaining best
attack requiring a physical loss of control over the AD file device or a
failure of existing IO protections.

Password use
------------
The user password is used to authenticate then decrypt the nonce and ciphertext
of the data encryption key. Changing the password often reduces the chance
that the same key and nonce will be used in XSalsa20, although with 192-bit
random nonces this is already very unlikely.

Currently, the user password is divided in half, the first half being used
to authenticate the header HMAC as `scrypt(lowhalf, authsalt)` 
and the second half being used to decrypt the data encryption key
as `scrypt(highhalf, cryptsalt)`.

On unmount, the XSalsa20 nonce and the two salts are randomized and written
to the AD file header along with the encryption of the data encryption key and
an HMAC authenticating the AD file.

Note
----

Requires libsodium >= 1.0.9

TODO
----
1. Should I just use the whole password for auth/crypt? One salt, two salts?
