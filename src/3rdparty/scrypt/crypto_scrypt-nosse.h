//
//  crypto_scrypt-nosse.h
//  Forgiva
//
//  Created by Marcus Frex on 03/11/2016.
//
//

#ifndef crypto_scrypt_nosse_h
#define crypto_scrypt_nosse_h


#include <stdint.h>
#include <string.h>

/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2 greater than 1.
 *
 * Return 0 on success; or -1 on error.
 */
int crypto_scrypt(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t,
				  uint32_t, uint32_t, uint8_t *, size_t);


#endif /* crypto_scrypt_nosse_h */
