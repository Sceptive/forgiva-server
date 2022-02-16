#include "common.h"
#include "debug.h"
#include "forgiva.h"
#include "3rdparty/scrypt/crypto_scrypt-nosse.h"
#include "3rdparty/argon2/argon2.h"


#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/*
	Hash algorithms will be used for metadata conversion.
*/
static f_byte *hash_algos_t0[] = {
	fstr("sha512"), fstr("sha384"), fstr("sha256"),
	fstr("sha224"), fstr("sha1"),   fstr("sha"),
	fstr("md5"),    fstr("md4"),    fstr("ripemd160")
};

static const int hash_algos_t0_size = 9;



/*
	Encryption algorithms will be used for metadata conversion.

	CBC is the default mode of operation to strengthen encryption against 
	various replay attacks for operations ECB and CFB; 
*/
static f_byte *enc_algos_t0[] = {
	fstr("des-ede3-cbc"),     fstr("camellia-128-cbc"),
	fstr("camellia-192-cbc"), fstr("camellia-256-cbc"),
	fstr("cast5-cbc"),        fstr("bf-cbc"),
	fstr("aes-128-cbc"),      fstr("aes-192-cbc"),
	fstr("aes-256-cbc")
};

static const int enc_algos_t0_size = 9;


/*

	Hardcoded name of animals for visual metadata selection.

*/
f_byte *animal_names[] = {
	fstr("Ape"),    fstr("Bat"),    fstr("Bear"), fstr("Whale"),
	fstr("Crow"),   fstr("Dog"),    fstr("Duck"), fstr("Cat"),
	fstr("Wasp"),   fstr("Fox"),    fstr("Gull"), fstr("Hyena"),
	fstr("Lion"),   fstr("Panda"),  fstr("Rat"),  fstr("Shark"),
	fstr("Spider"), fstr("Turtle"), fstr("Wolf"), fstr("Zebra")
};

int F_ANIMAL_COUNT = 20;

/*
	For password generation this is the default alphabet for selections.

	Any off-the-shelf fork may/can/should change the alphabet order.
*/
static char *lower_case_chars = "qwertyuiopasdfghjklzxcvbnm\0";
static char *upper_case_chars = "QWERTYUIOPASDFGHJKLZXCVBNM\0";
static char *number_chars     = "0123456789\0";
static char *symbol_chars     = ".@+-*/%_!,#$;\\()><=^&{}\0";


/*
	Characters for simple mode of password generation
*/

static char *password_chars[] = {
	"q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "a", "s", "d", "f", "g",
	"h", "j", "k", "l", "z", "x", "c", "v", "b", "n", "m", "Q", "W", "E", "R",
	"T", "Y", "U", "I", "O", "P", "A", "S", "D", "F", "G", "H", "J", "K", "L",
	"Z", "X", "C", "V", "B", "N", "M", "0", "1", "2", "3", "4", "5", "6", "7",
	"8", "9", ".", "@", "+", "-", "*", "/", "%", "_", "!", ","
};

static const int password_chars_size = 72;

/*
	Characters for medium mode of password generation
*/

static char *password_chars_intermediate[] = {
	"q", "w", "e", "r", "t", "y", "u",  "i", "o", "p", "a", "s",  "d", "f",
	"g", "h", "j", "k", "l", "z", "x",  "c", "v", "b", "n", "m",  "Q", "W",
	"E", "R", "T", "Y", "U", "I", "O",  "P", "A", "S", "D", "F",  "G", "H",
	"J", "K", "L", "Z", "X", "C", "V",  "B", "N", "M", "0", "1",  "2", "3",
	"4", "5", "6", "7", "8", "9", ".",  "@", "+", "-", "*", "/",  "%", "_",
	"!", ",", "|", "#", "$", ";", "\\", "(", ")", ">", "<", "\"", "="
};

static const int password_chars_intermediate_size = 83;

/*
	Characters for advanced mode of password generation
*/

static char *password_chars_advanced[] = {
	"q", "w", "e", "r", "t", "y", "u",  "i", "o", "p", "a", "s",  "d", "f",
	"g", "h", "j", "k", "l", "z", "x",  "c", "v", "b", "n", "m",  "Q", "W",
	"E", "R", "T", "Y", "U", "I", "O",  "P", "A", "S", "D", "F",  "G", "H",
	"J", "K", "L", "Z", "X", "C", "V",  "B", "N", "M", "0", "1",  "2", "3",
	"4", "5", "6", "7", "8", "9", ".",  "@", "+", "-", "*", "/",  "%", "_",
	"!", ",", "|", "#", "$", ";", "\\", "(", ")", ">", "<", "\"", "=", "´",
	"~", "£", "¢", "§", "^", "&", "±",  "{", "}"
};

static const int password_chars_advanced_size = 93;


/*
	Default salt for operations. 

	//TODO: Should add a configuration value to customize default salt
*/
static f_byte default_salt[]    = {'f', 'o', 'r', 'g', 'i', 'v', 'a'};
static int default_salt_size    = 7;
static f_uint default_iteration = 10000;


/*

	Initial hashing of password provided by user.

*/
byte_data *forgiva_initial_password_hash(byte_data *pass)
{

#ifdef FORGIVA_DEBUG
	forgiva_debug_d(F_DEBUG_INTERMEDIATE, 
			fstr("forgiva_initial_password_hash:"), 
			pass->data, 
			pass->len);
#endif


	//TODO: Should add a configuration value to customize default initial 
	//		hashing algo.

	byte_data *fh = forgiva_hash("sha512", pass->data, pass->len);
	return fh;
}



/*



*/
animal_pass_pair *forgiva_generate_passes(forgiva_options *opts)
{

	// Check validity of options
	if (opts->host == NULL ||
		opts->account == NULL ||
		opts->animal == NULL) {

#ifdef FORGIVA_DEBUG
	forgiva_debug_s(fstr("Invalid options"));	
#endif			

			return NULL;
	}


	// Initialize function variables
	animal_pass_pair *ret 	= f_malloc(F_ANIMAL_COUNT * 
													sizeof(animal_pass_pair));
	byte_data *salt 		= forgiva_encrypted_inputs(opts);

#ifdef FORGIVA_DEBUG
	forgiva_debug_d(F_DEBUG_INTERMEDIATE, fstr("Salt:"), salt->data, salt->len);
#endif

	byte_data *key 			= f_byte_data_dup(opts->password_hash);

#ifdef FORGIVA_DEBUG
	forgiva_debug_d(F_DEBUG_INTERMEDIATE, fstr("Clear key:"), key->data,
					key->len);
#endif

	// Regarding complexity key derivation function strength gets increased

	if (opts->complexity == FORGIVA_PG_INTERMEDIATE) {

		byte_data *key_intermediate = forgiva_PKCS5_PBKDF2_HMAC_SHA(key, 
																	salt, 2);

		f_byte_data_free(key);
		key = key_intermediate;

	} else if (opts->complexity == FORGIVA_PG_ADVANCED) {

		byte_data *key_advanced     = forgiva_PKCS5_PBKDF2_HMAC_SHA(key, 
																	salt, 3);

		f_byte_data_free(key);
		key = key_advanced;
	}

#ifdef FORGIVA_DEBUG
	forgiva_debug_d(F_DEBUG_INTERMEDIATE, fstr("Encryption key:"), key->data,
					key->len);
#endif


	// If SCrypt is enabled then push key throught SCrypt algorithm.

	if (opts->use_scrypt == true) {
		f_byte *n_key 			= f_malloc(32);


		// Launching SCrypt with default parameters
		// TODO: Should add respective configuration values to customize 
		//		 SCrypt default values.
		crypto_scrypt(key->data, key->len, salt->data, salt->len, 
							131072, 8, 1, n_key, 32);

		byte_data *scrypt_key 	= f_byte_data_new_with_data(n_key, 32);

		// Freeing memory
		f_byte_data_free(key);
		f_free(n_key);

		// Overriding key
		key = scrypt_key;
	}

	// If Argon is enabled then push key throught Argon2 algorithm.

	if (opts->use_argon2 == true) {

		f_byte *n_key 			= f_malloc(32);

		// Launching Argon2d with default parameters
		// TODO: Should add respective configuration values to customize 
		//       Argon2 default values.
		argon2d_hash_raw(2, (1<<16), 1, key->data, key->len, salt->data, 
							salt->len, n_key, 32);

		byte_data *argon2_key 	= f_byte_data_new_with_data(n_key, 32);

		// Freeing memory
		f_byte_data_free(key);
		f_free(n_key);

		// Overriding key
		key = argon2_key;

	}

	// Please bear in mind that output is very relative to coding order. 
	// First SCrypt and second Argon2 is specified. Otherwise output will 
	//change.

	// Generating passwords for each animal.
	for (int i = 0; i < F_ANIMAL_COUNT; i++) {

		byte_data *g_cipher = forgiva_PKCS5_PBKDF2_HMAC_SHA1(key, salt);

		f_byte_data_free(key);
		key 				= f_byte_data_dup(g_cipher);
		f_byte *password 	= hash_to_password(key, opts->character_length, 
												opts);
		ret[i].animal_name 	= animal_names[i];
		ret[i].password 	= f_byte_data_new_with_data(password,
								opts->character_length+1);
		ret[i].password->data[opts->character_length] = '\0';
		f_free(password);
		f_byte_data_free(g_cipher);
	}

	// Freeing memory
	f_byte_data_free(salt);
	f_byte_data_free(key);

	return ret;
}

/*
	Returns back results as JSon given certain options to generate passwords.
*/
f_byte	            *forgiva_generate_pass_as_json(forgiva_options *options)  {

	animal_pass_pair    *ht     = forgiva_generate_passes(options);
	f_byte              *ret    = NULL;
	if (ht != NULL) {
		for (int i = 0; i < F_ANIMAL_COUNT; i++) {
			if (strcasecmp(options->animal,ht[i].animal_name) == 0) {
				// Before rendering to JSON, to remove \0 from password hex
				// we subtract length by 1
				if (ht[i].password->len > 1) {
					ht[i].password->len--;
				}
				ret = serialize_result_to_json(ht[i].animal_name,
					ht[i].password);
			}
			
			// Cleanup
			f_byte_data_free(ht[i].password);
		}
	}
	f_free(ht);
	return ret;
}

/*
	Launches digest operations on given EVP_MD object.
*/
byte_data *digest(const EVP_MD *md, f_byte *data, int size)
{

	byte_data *ret = f_byte_data_new(sizeof(f_byte) * md->md_size);
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, data, size);
	EVP_DigestFinal_ex(mdctx, ret->data, &ret->len);
	EVP_MD_CTX_destroy(mdctx);

	return ret;
}


     

/*

	Returns hash of the data with specified hash algorithm name (hash_name)

	The key thing with this function is it will return hash output as minimum
	as the length of hash block size.

	Let's say if block size of the hash algorithm is 8 bytes and the data is 10
	bytes, it returns 10 bytes of hash. 

    For ex. with the block size of 8 and with and imaginary hash algorithm 
	result length will be just as the same as below.

    +-----------+----------------------+
	| Value     |  Hash                |
	+-----------+----------------------+
	| abc       |  deffha0293019302    |
	| abcdefgh  |  0001020304050607    |
	| abcdefghi |  aabbccddeeffgghh01  |
	+-----------+----------------------+

	Main reason to do this is strengthening hash collision possibilities 
	theoritically there is no proof that this actually works.

*/
byte_data *forgiva_hash(const char *hash_name, f_byte *data, int size)
{

	const EVP_MD *md;
	md = EVP_get_digestbyname(hash_name);

	if (!md) {
		if (strcicmp(hash_name, "sha512") == 0) {
			md = EVP_sha512();
		} else if (strcicmp(hash_name, "sha384") == 0) {
			md = EVP_sha384();
		} else if (strcicmp(hash_name, "sha256") == 0) {
			md = EVP_sha256();
		} else if (strcicmp(hash_name, "sha224") == 0) {
			md = EVP_sha224();
		} else if (strcicmp(hash_name, "sha1") == 0) {
			md = EVP_sha1();
		} else if (strcicmp(hash_name, "sha") == 0) {
			md = EVP_sha();
		} else if (strcicmp(hash_name, "md5") == 0) {
			md = EVP_md5();
		} else if (strcicmp(hash_name, "md4") == 0) {
			md = EVP_md4();
		} else if (strcicmp(hash_name, "ripemd160") == 0) {
			md = EVP_ripemd160();
		}
	}

	// Fail if an unknown digest specified
	if (!md) {
		FATAL("Unknown message digest %s\n", hash_name);
	}

#ifdef FORGIVA_DEBUG
	forgiva_debug(F_DEBUG_ADVANCED, fstr("forgiva_hash in"), data, size,
		" name: %s ds: %d ", hash_name, md->md_size);
#endif

	byte_data *ret; 

	// If hash block size is smaller than data size
	if (md->md_size < size) {

		// Index of cursor
		int idx 			= 0;
		// Target block size to fill in
		int tgt_block_size  = md->md_size;
		// Returning value
		ret = f_byte_data_new(sizeof(f_byte) * size);

		while (true) {

			// Block size which will be filled in
			int block_size 	= tgt_block_size - idx;
			// Input block
			f_byte *inblock = f_malloc(sizeof(f_byte) * block_size);
			// Copy left data into input block
			memcpy(inblock, data + idx, tgt_block_size - idx);

#ifdef FORGIVA_DEBUG
			forgiva_debug_d(F_DEBUG_ADVANCED, fstr("INBLOCK: "), 
					inblock, block_size);
#endif

			// Get digest into output block
			byte_data *outblock = digest(md, inblock, block_size);

#ifdef FORGIVA_DEBUG
			forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("OUTBLOCK: "), outblock);
#endif

			// Fill up return value starting from the cursor till the target 
			// block size
			for (int i = idx; i < tgt_block_size; i++) {
				ret->data[i] = outblock->data[i - idx];
			}

#ifdef FORGIVA_DEBUG
			forgiva_debug_d(F_DEBUG_ADVANCED, fstr("NRET: "), ret->data, 
																tgt_block_size);
#endif

			// Move cursor to target block size
			idx = tgt_block_size;

			// If cursor reaches to the end then free the memory and break 
			// the loop 
			if (idx >= size) {
				f_free(inblock);
				f_byte_data_free(outblock);
				break;
			}

			// Enlarge target block size
			tgt_block_size = idx + md->md_size;

			// If target block size gets bigger than the 
			// expected block size then limit it 
			if (tgt_block_size > size)
				tgt_block_size = size;


			// Free the memory
			f_free(inblock);
			f_byte_data_free(outblock);
		}

	} else {
		// Return specific digest
		ret = digest(md, data, size);
	}

#ifdef FORGIVA_DEBUG
	forgiva_debug(F_DEBUG_ADVANCED, fstr("forgiva_hash out"), ret->data, 
		ret->len,
		" name: %s", hash_name);
#endif

	return ret;
}



/*
	Returns a key from password and salt regarding specifications within
   	RFC 2898 documentation.


	Additionally hashing algorithm changes with type parameter from simple (1)
	, medium (2) to advanced (3)
*/
byte_data *forgiva_PKCS5_PBKDF2_HMAC_SHA(
	byte_data *password, 
	byte_data *salt,
	int type)
{

	f_byte *key = f_malloc(32);

	if (type == 1) {
		if (PKCS5_PBKDF2_HMAC_SHA1(
			fcstr(password->data), 
					password->len, 
					(unsigned char *)salt->data, 
					salt->len,
					default_iteration, 
					32, 
					(unsigned char *)key) == 0) {
			FATAL("Cannot generate key");
	};
	} else if (type == 2) {
		if (PKCS5_PBKDF2_HMAC(fcstr(password->data), password->len,
			(unsigned char *)salt->data, salt->len,
			default_iteration * 1000, EVP_sha256(), 32,
			(unsigned char *)key) == 0) {
			FATAL("Cannot generate key");
		};
	} else if (type == 3) {
		if (PKCS5_PBKDF2_HMAC(fcstr(password->data), password->len,
			(unsigned char *)salt->data, salt->len,
			default_iteration * 10000, EVP_sha512(), 32,
			(unsigned char *)key) == 0) {
			FATAL("Cannot generate key");
		};
	}

	byte_data *ret = f_byte_data_new_with_data(key, 32);
	f_free(key);
	return ret;
}

byte_data *forgiva_PKCS5_PBKDF2_HMAC_SHA1(byte_data *password, 
										  byte_data *salt)
{

	return forgiva_PKCS5_PBKDF2_HMAC_SHA(password, salt, 1);
}

byte_data *forgiva_PKCS5_PBKDF2_HMAC_SHA256(byte_data *password, 
											byte_data *salt)
{

	return forgiva_PKCS5_PBKDF2_HMAC_SHA(password, salt, 2);
}

byte_data *forgiva_PKCS5_PBKDF2_HMAC_SHA512(byte_data *password, 
									        byte_data *salt)
{

	return forgiva_PKCS5_PBKDF2_HMAC_SHA(password, salt, 3);
}


/*
	Returns encrypted data specified with the alg* parametr using input val* 
	and encrypts it with key* and *iv values respectively.
*/
byte_data *forgiva_crypt_ext(const char *alg, 
					byte_data *val, 
					byte_data *key,
					byte_data *iv)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;

	ctx 				 = EVP_CIPHER_CTX_new();

	cipher = EVP_get_cipherbyname(alg);

	if (!cipher) {
		if (strcicmp(alg, "des-ede3-cbc") == 0) {
			cipher = EVP_des_ede3_cbc();
		} else if (strcicmp(alg, "camellia-128-cbc") == 0) {
			cipher = EVP_camellia_128_cbc();
		} else if (strcicmp(alg, "camellia-192-cbc") == 0) {
			cipher = EVP_camellia_192_cbc();
		} else if (strcicmp(alg, "camellia-256-cbc") == 0) {
			cipher = EVP_camellia_256_cbc();
		} else if (strcicmp(alg, "cast5-cbc") == 0) {
			cipher = EVP_cast5_cbc();
		} else if (strcicmp(alg, "aes-128-cbc") == 0) {
			cipher = EVP_aes_128_cbc();
		} else if (strcicmp(alg, "aes-192-cbc") == 0) {
			cipher = EVP_aes_192_cbc();
		} else if (strcicmp(alg, "aes-256-cbc") == 0) {
			cipher = EVP_aes_256_cbc();
		} else if (strcicmp(alg, "bf-cbc") == 0) {
			cipher = EVP_bf_cbc();
		}
	}

	if (!cipher) {
		FATAL("Unsupported cipher algorithm %s", alg);
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	f_byte *enc_key = f_malloc(cipher->key_len);
	f_byte *enc_iv = cipher->iv_len > 0 ? f_malloc(cipher->iv_len) : NULL;

	memcpy(enc_key, key->data,
		key->len < (f_uint)cipher->key_len ? key->len : cipher->key_len);
	if (cipher->iv_len > 0)
		memcpy(enc_iv, iv->data,
			iv->len < (f_uint)cipher->iv_len ? iv->len : cipher->iv_len);

	f_byte *cipher_t = (f_byte *)malloc(val->len + cipher->block_size);
	int output_len;

#ifdef FORGIVA_DEBUG

	forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("F_Encrypt in val"), val->data,
		val->len,
		"F_Encrypt Algorithm: %s key size: %d iv size: %d block size: ",
		alg, cipher->key_len, cipher->iv_len, cipher->block_size);
	forgiva_debug_d(F_DEBUG_INTERMEDIATE, fstr("F_Encrypt enc key"), enc_key,
		cipher->key_len);

	if (cipher->iv_len > 0)
		forgiva_debug_d(F_DEBUG_INTERMEDIATE, fstr("F_Encrypt iv key"), enc_iv,
						cipher->iv_len);

#endif


	byte_data *data = f_byte_data_dup(val);


	if (data->len % cipher->block_size != 0) {
		f_byte_data_free(data);
		int tot = cipher->block_size + val->len;
		int new_size = (tot - (tot % cipher->block_size));
		data = f_byte_data_new(new_size);
		memcpy(data->data, val->data, val->len);
	}

	/**
		We don't need EVP_CipherFinal_ex because we already making
		sure that we fit into multiple of block size and whole en-
		cryption is done within EVP_CipherUpdate
	**/
	if (!EVP_CipherInit_ex(
		ctx, cipher, NULL, (unsigned char *)enc_key,
		cipher->iv_len > 0 ? (const unsigned char *)enc_iv : NULL, 1) ||
		!EVP_CipherUpdate(ctx, (unsigned char *)cipher_t, &output_len,
		(unsigned char *)data->data, data->len)) {
		return 0;
	}


#ifdef FORGIVA_DEBUG

	forgiva_debug(F_MAX_DEBUG_LEVEL, fstr("F_Encrypt OUT"), cipher_t, 
		output_len,
		"inl: %d len: %d bs: %d\n", 
		val->len, 
		output_len,  
		cipher->block_size);
#endif

	byte_data *ret = f_byte_data_new_with_data(cipher_t, output_len);


	// Empty memory
	f_free(cipher_t);
	f_free(enc_key);
	f_free(enc_iv);
	f_byte_data_free(data);

	// Clear cipher context
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}


/*

	Encrypts input (val) with key (key) using algorithm (alg) specified using 
	default salt, RFC 2988 derived key and hashed keys value as IV.

*/
byte_data *forgiva_encrypt(const char *alg, 
		f_byte *val, 
		f_uint val_size,
		f_byte *key, 
		f_uint key_size)
{

	// Clone of key
	byte_data *b_key 	= f_byte_data_new_with_data(key, key_size);
	// Default salt
	byte_data *b_salt   =
		f_byte_data_new_with_data(default_salt, default_salt_size);
	// Clone of value
	byte_data *bd_val 	= f_byte_data_new_with_data(val, val_size);

	// Derived key from key using RFC 2988
	byte_data *c_key 	= forgiva_PKCS5_PBKDF2_HMAC_SHA1(b_key, b_salt);
	// IV value from original key
	byte_data *iv_b		= forgiva_hash("sha512", key, key_size);
	// Encrypted data with parameters above
	byte_data *ret 		= forgiva_crypt_ext(alg, bd_val, c_key, iv_b);

	if (ret == 0)
		FATAL("Failed to encrypt %s", alg);


	// Free memory
	f_byte_data_free(b_key);
	f_byte_data_free(b_salt);
	f_byte_data_free(c_key);
	f_byte_data_free(iv_b);
	f_byte_data_free(bd_val);

	return ret;
}


/*
	Check if value (_val) contains specific character (_chr)
*/
f_bool contains(f_byte *_val,f_byte _chr) {

	for (int i=0;i<strlen(_val);i++) {
		if ( (_val[i]) == _chr) {
			return true;
		}
	}

	return false;
}


/*

	Old way of converting a specific hash to password. This algorithm is used 
	within Kyle and open source Forgiva command line versions. With this 
	algorithm all the character types can be used within the specific 
	alphabet and it is impossible to specify only char, number, upper case, 
	symbol vice versa.

	Put here just for backward compatibility only.

*/
f_byte *hash_to_password_legacy(byte_data *hash, 
								int max_len, 
								forgiva_options *opts)
{

	f_byte *ret = NULL;

	// to be sure it is long enough
	byte_data *hashed = forgiva_initial_password_hash(hash);

	// Regarding complexity parameter put respective character from the alphabet
	// into the generated password value
	for (int i = 0; i < max_len; i++) {
		f_byte *char_to_add = fstr(
			(opts->complexity == FORGIVA_PG_INTERMEDIATE
				? password_chars_intermediate[((int)hashed->data[i] % 
											password_chars_intermediate_size)]
				: (opts->complexity == FORGIVA_PG_ADVANCED
					? password_chars_advanced[((int)hashed->data[i] %
						password_chars_advanced_size)]
							: password_chars[(int)hashed->data[i] %
								password_chars_size])));

		if (ret == NULL) {
#ifdef WIN32
#define strdup(x) _strdup(x)
#endif

			ret = fstr(strdup(fcstr(char_to_add)));
		} else {

			f_byte *ret_new = fstr(concat(2, ret, char_to_add));

			f_free(ret);

			ret = ret_new;
		}
	}

#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASH_TO_PASSWORD -> IN"), hash);
	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASH_TO_PASSWORD -> HASHED"),
		hashed);
	forgiva_debug_d(F_DEBUG_ADVANCED, fstr("HASH_TO_PASSWORD -> OUT"), ret,
					max_len);
#endif

	f_byte_data_free(hashed);

	return ret;
}



/*

	Converts a hash value (an array of bytes) into password specified with the
	inclusive and exclusive character sets.

	First it creates an alphabet with the required character sets. Secondly it 
	converts generated hash into and array of characters by lookups from the 
	alphabet. And finally it scans for the block from the generated big 
	password until it can find a proper password value fullfills the 
	requirement. If it can't then it generates hash of hash and starts 
	to rescan the content until it finds a proper password. There is 
	no guarantee that this function finds a proper password in a short amount
	of time, maybe a mathematical proof needed that this function generates
	a fulfilled password in an acceptable time span. But experiments showed
	no bottleneck for years for this function.

	Example run >>

	Inputs:

	> Expected quality 
		Lowercase: true 
		Uppercase: true 
		Symbols:   true
		Numbers:   true
		Length:    4
	> Hash: 01020304050607080910111213151617

	1. Pass: a1dBu+312_dE042kd

	2. Nominee password: a1dB => fulfills: false
	   Nominee password: 1dbu => fulfills: false
	   Nominee password: dBu+ => fulfills: true

	   If all nominees those not fulfills updates hash with 
		forgiva_initial_password_hash(hash) (SHA512) 

	3. Returns "dBu+"

*/
f_byte *hash_to_password(byte_data *hash, int max_len, forgiva_options *opts)
{

	if (opts->use_legacy) {
		return hash_to_password_legacy(hash,max_len,opts);
	}

#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASH_TO_PASSWORD -> IN"), hash);

#endif

	// Returning value
	f_byte *ret 				= NULL;
	// Returning value length
	int		ret_len 			= 0;
	// Score to fulfill expected quality
	int required_score 			= 0;
	// Length of alphabet which willbe used in password creation
	int alphabet_len 			= 0;
	// Index indicator which will be used in various steps
	int idx	 					= 0;
	// Alphabet 
	f_byte *alphabet			= NULL;
	// Indicator which final password has lower case character
	f_bool has_lowercase 		= false;
	// Indicator which final password has upper case character
	f_bool has_uppercase 		= false;
	// Indicator which final password has numbers
	f_bool has_numbers   		= false;
	// Indicator which final password has symbols
	f_bool has_symbols	 		= false;
	// Score of tested password for fulfillment
	int current_score			 = 0;
	// Nominee password to get tested for fulfillment
	f_byte *nominee_password     = NULL;
	// New hashed value of inter usage
	byte_data *new_hashed		 = NULL;
	// Hashed value of password
	byte_data *hashed			 = NULL;

	/*

		Set alphabet length and required score regarding options

	*/
	if (opts->chr_lowercase == true) {
		alphabet_len  += strlen(lower_case_chars);
		required_score++;
	}

	if (opts->chr_uppercase == true) {
		alphabet_len  += strlen(upper_case_chars);
		required_score++;
	}

	if (opts->chr_numbers == true) {
		alphabet_len  += strlen(number_chars);
		required_score++;
	}

	if (opts->chr_symbols == true) {
		alphabet_len  += strlen(symbol_chars);
		required_score++;
	}

	alphabet = f_malloc(alphabet_len+1);

	/*
		 Generate alphabet for the requirements
	*/
	if (opts->chr_lowercase == true) {
		for (int i=0;i<strlen(lower_case_chars);i++) {
			alphabet[idx] = lower_case_chars[i];
			idx++;
		}
	}

	if (opts->chr_uppercase == true) {
		for (int i=0;i<strlen(upper_case_chars);i++) {
			alphabet[idx] = upper_case_chars[i];
			idx++;
		}
	}

	if (opts->chr_numbers == true) {
		for (int i=0;i<strlen(number_chars);i++) {
			alphabet[idx] = number_chars[i];
			idx++;
		}
	}


	if (opts->chr_symbols == true) {
		for (int i=0;i<strlen(symbol_chars);i++) {
			alphabet[idx] = symbol_chars[i];
			idx++;
		}
	}

	alphabet[idx+1] = '\0';


#ifdef FORGIVA_DEBUG
	forgiva_debug_n(F_DEBUG_ADVANCED,"alphabet: %s",alphabet);
#endif

	

	// To be sure it is long enough rehashing
	hashed = forgiva_initial_password_hash(hash);
	
	// Do not stop until reaching expected character length
	while (ret_len < opts->character_length) {
	
		// 
		for (int i=0;i<hashed->len;i++) {
			// Getting character value at the index
			char val 			= hashed->data[i];
			// Converting value to unsigned int
			uint16_t ui_val 	= 0x0 << 24 | val & 0xff;
			// Alphabet index of int value of character
			int alphabet_idx	=  ui_val % alphabet_len;
			// Character at alphabet index
			char append			= alphabet[alphabet_idx];


			// If return value not initialized 
			// then initialize and append
			if (ret == NULL) {
				
				ret = f_malloc(2);
				ret[0] = append;
				ret[1] = '\0';
				ret_len++;

			} 
			// If return value is already initialized
			// then append the new character
			else {
				
				int l = strlen(ret);
				f_byte *ret_new = f_malloc(l+2);
				strcpy(ret_new,ret);
				ret_new[l] = append;
				ret_new[l+1] = '\0';
				f_free(ret);
				ret = ret_new;
			}
			// Increase the returning length
			ret_len++;

		}


		for (int i=0;i<strlen(ret) - opts->character_length;i++) {
			// Alloc for new nominee
			nominee_password = f_malloc(opts->character_length+1);
			// Copy from the array ret value
			memcpy(nominee_password,ret+i,opts->character_length);
			// Put null to bound in
			nominee_password[opts->character_length] = '\0';

			// Cleaning expected values
			has_lowercase 	= false;
			has_uppercase 	= false;
			has_numbers   	= false;
			has_symbols	 	= false;
			current_score 	= 0;

			// Check if has lower case character
			for (int ii=0;ii<strlen(lower_case_chars);ii++) {
				if (contains(nominee_password,lower_case_chars[ii])) {
					has_lowercase = true;
					break;
				}
			}

			// Check if has lower case character
			for (int ii=0;ii<strlen(upper_case_chars);ii++) {
				if (contains(nominee_password,upper_case_chars[ii])) {
					has_uppercase = true;
					break;
				}
			}


			for (int ii=0;ii<strlen(number_chars);ii++) {
				if (contains(nominee_password,number_chars[ii])) {
					has_numbers = true;
					break;
				}
			}

			for (int ii=0;ii<strlen(symbol_chars);ii++) {
				if (contains(nominee_password,symbol_chars[ii])) {
					has_symbols = true;
					break;
				}
			}

			// If password has lower case and it is expected then increase score
			if (has_lowercase && opts->chr_lowercase) {
				current_score++;
			}

			// If password has upper case and it is expected then increase score
			if (has_uppercase && opts->chr_uppercase) {
				current_score++;
			}

			// If password has number and it is expected then increase score
			if (has_numbers && opts->chr_numbers) {
				current_score++;
			}

			// If password has symbol and it is expected then increase score
			if (has_symbols && opts->chr_symbols) {
				current_score++;
			}

			// If password's score is as required then return the password
			if (current_score == required_score) {
				f_free(ret);
				ret = nominee_password;
				f_byte_data_free(hashed);
				return ret;
			} else {
				f_free(nominee_password);
			}

		}


		// Rehash new hash value and start iteration from the begining
		new_hashed = forgiva_initial_password_hash(hashed);
		f_byte_data_free(hashed);
		hashed = new_hashed;

	}


#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASH_TO_PASSWORD -> HASHED"),
		hashed);
	forgiva_debug_d(F_DEBUG_ADVANCED, fstr("HASH_TO_PASSWORD -> OUT"), ret,
					max_len);
#endif


	return ret;
}

/*
	Regarding each character in the "val" and hash algorithm amount,
	runs various hash algorithms over generated hash.

	So that hashing process gets protected by other algorithms like;

		a(b(c(d(e(data)))))

	If an algorithm gets weaker then b if b then c algorithms sustains
	strength.

*/
byte_data *forgiva_iterative_hash(byte_data *val)
{
	// Return value
	byte_data *ret 		= f_byte_data_dup(val);
	// Algorithm to be used in iteration
	f_byte *algorithm 	= NULL;
	// Result of the hashing
	byte_data *hashed	= NULL;


#ifdef FORGIVA_DEBUG
	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("forgiva_iterative_hash in "), val);
#endif

	for (f_uint i = 0; i < val->len; i++) {
		int rem 			= ((int)val->data[i] % hash_algos_t0_size);
		algorithm 			= hash_algos_t0[rem];
		hashed				= forgiva_hash(fcstr(algorithm), 
											ret->data, ret->len);
#ifdef FORGIVA_DEBUG
		forgiva_debug_n(F_DEBUG_ADVANCED, "%p %p ", ret, hashed);
#endif
		f_byte_data_free(ret);
		ret = f_byte_data_dup(hashed);
		f_byte_data_free(hashed);
	}

#ifdef FORGIVA_DEBUG
	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("forgiva_iterative_hash out "), 
					ret);
#endif

	return ret;
}


/*

	Just like the iterative hashing method data gets encrypted over and over
	again with respective values within value (val).

	This function does not provides any protection for any cryptographic
	attacks but increases resistance for the brute force attacks by spending 
	a considerable amount of time 

*/
byte_data *forgiva_iterative_encrypt(byte_data *val, byte_data *key)
{
	// Return value
	byte_data *ret 			= f_byte_data_dup(val);
	// Algorithm to be used in iteration
	f_byte *algorithm		= NULL;
	// Result of the hashing
	byte_data *encrypted 	= NULL;

	for (f_uint i = 0; i < val->len; i++) {
		int rem 	= ((int)val->data[i] % enc_algos_t0_size);
		algorithm 	= enc_algos_t0[rem];
		encrypted 	= forgiva_encrypt(fcstr(algorithm), 
			ret->data,
			ret->len, 
			key->data, 
			key->len);


		f_byte_data_free(ret);
		ret = f_byte_data_dup(encrypted);
		f_byte_data_free(encrypted);
	}

	return ret;
}


/*

	Hashing the hash value of a value. Expected to increase strength against
	the collision attacks from big domain to small domain hashing. Please 
	bear in mind that ordinary way of hashing a value is iterative hashing
	defined in forgiva_iterative_hash function. Most of the resistance tied
	with time span required make the calculations forward and backwards.

	For example;

	| Value | Hashed Value | Rehashed Value |
	|   a   |       1      |        m       |
	|   b   |       2      |        n       |
	|   c   |       3      |        u       |
	|   d   |       3      |        u       |

	On the table above c and d are collisioned but second hashing makes it 
	hard to reach back to collisioned value 3 to further attack back to the
	original value.


*/
byte_data *forgiva_hash_twice(byte_data *val)
{

	byte_data *first 	= forgiva_iterative_hash(val);
	byte_data *second	= forgiva_iterative_hash(first);

	f_byte_data_free(first);

	return second;
}



/*

	One way encryption of input values described within Forgiva algorithm

*/
byte_data *forgiva_encrypted_inputs(forgiva_options *opts)
{
	byte_data *hashed_master_password = NULL;
	byte_data *hostname				  = NULL;
	byte_data *account				  = NULL;
	byte_data *hashed_hostname		  = NULL;
	byte_data *hashed_account 		  = NULL;
	// First phase value of encryption
	byte_data *encrypt_01			  = NULL;
	// First and second tier phase value of encryption
	byte_data *encrypt_01t			  = NULL;
	// Renewal date of generation
	byte_data *hashed_generation	  = NULL;
	// Second phase value of encryption
	byte_data *encrypt_02			  = NULL;
	// Returning value
	byte_data *ret 					  = NULL;
	// Final value with signature processed
	byte_data *signed_ret			  = NULL;

#ifdef FORGIVA_DEBUG

	forgiva_debug_s(fstr("forgiva_encrypted_inputs"));

#endif

	hashed_master_password 	= forgiva_hash_twice(opts->password_hash);
	hostname 				= f_byte_data_new_with_data(opts->host, 
									strlen(fcstr(opts->host)));
	account 				= f_byte_data_new_with_data(opts->account, 
									strlen(fcstr(opts->account)));

#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HOSTNAME"), hostname);
	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("ACCOUNT"), account);
#endif

	hashed_hostname 	= forgiva_hash_twice(hostname);
	hashed_account 		= forgiva_hash_twice(account);

	f_byte_data_free(hostname);
	f_byte_data_free(account);

	encrypt_01 =
		forgiva_iterative_encrypt(hashed_hostname, hashed_account);

#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASHED HOSTNAME"), 
						hashed_hostname);
	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASHED ACCOUNT"), 
						hashed_account);
#endif

	f_byte_data_free(hashed_hostname);
	f_byte_data_free(hashed_account);

	encrypt_01t =
		forgiva_iterative_encrypt(encrypt_01, hashed_master_password);

	f_byte_data_free(encrypt_01);

	encrypt_01 = f_byte_data_dup(encrypt_01t);

	f_byte_data_free(encrypt_01t);

#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("ENCRYPT 01"), encrypt_01);
#endif

	if (opts->renewal_date == NULL || opts->renewal_date->len == 0) {
		if (opts->renewal_date != NULL) {
			f_byte_data_free(opts->renewal_date);
		}
		opts->renewal_date = 
					f_byte_data_new_with_str((const f_byte *) "1970-01-01");
	}

	hashed_generation = forgiva_hash_twice(opts->renewal_date) ;

	encrypt_02 =
		forgiva_iterative_encrypt(hashed_generation, hashed_master_password);

#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASHED GENERATION"),
		hashed_generation);
	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("HASHED M.PASSWORD"),
		hashed_master_password);
#endif

	f_byte_data_free(hashed_generation);
	f_byte_data_free(hashed_master_password);

#ifdef FORGIVA_DEBUG

	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("ENCRYPT 02"), encrypt_02);
#endif

	ret = forgiva_iterative_encrypt(encrypt_01, encrypt_02);

	if (opts->signature != NULL && opts->signature->len > 0) {
#ifdef FORGIVA_DEBUG

		forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("SIGNATURE"), opts->signature);
#endif

		signed_ret = forgiva_iterative_encrypt(ret, opts->signature);

		f_byte_data_free(ret);

		ret = signed_ret;
	}
#ifdef FORGIVA_DEBUG


	forgiva_debug_bd(F_DEBUG_ADVANCED, fstr("ENCRYPTED INPUTS"), ret);
#endif

	f_byte_data_free(encrypt_01);
	f_byte_data_free(encrypt_02);

	return ret;
}
