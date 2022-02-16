#include "types.h"

#ifndef _HAVE_FORGIVA_H
#define _HAVE_FORGIVA_H

extern f_byte *animal_names[];

extern int F_ANIMAL_COUNT;
/*
	Returns hash table contains animal names and passwords in character length
	specified.
*/
animal_pass_pair    *forgiva_generate_passes(forgiva_options *opts);

/*
	Returns animal - password pair as JSON result containing
	only specified animal
*/
f_byte	            *forgiva_generate_pass_as_json(forgiva_options *opts);

/*
	Calculates SHA512 version of the password
*/
byte_data			*forgiva_initial_password_hash(byte_data *pass);

/*
	Calculates hash of the "data" regarding "hash_name" algorithm.
*/
byte_data			*forgiva_hash(const char *hash_name, f_byte *data, 
									int size);

/*
	Encrypts "val" with the "key" using algorithm named "alg" with
	"key"'s sha512 hash as IV.
*/
byte_data			*forgiva_encrypt(const char *alg, f_byte *val, 
						f_uint val_size,
						f_byte *key, f_uint key_size);
/*
	Encrypts "val" with the "key" and "iv" using algorithm typed within "alg".
*/
byte_data			*forgiva_crypt_ext(const char *alg, byte_data *val, 
						byte_data *key,
						byte_data *iv);

/*
	Runs PKCS5_PBKDF2_HMAC_SHA algorithm tied with type.
*/
byte_data			*forgiva_PKCS5_PBKDF2_HMAC_SHA(byte_data *key, 
						byte_data *salt,
						int type);
/*
	Runs PKCS5_PBKDF2_HMAC_SHA1 algorithm on key and salt.
*/
byte_data			*forgiva_PKCS5_PBKDF2_HMAC_SHA1(byte_data *key, 
													byte_data *salt);

/*
	Converts final hash value to specified password type.
*/
f_byte				*hash_to_password(byte_data *hash, 
										int max_len, 
										forgiva_options *opts);


byte_data			*forgiva_encrypted_inputs(forgiva_options *opts);

#endif