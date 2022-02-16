#ifndef __HAVE_TYPES_H
#define __HAVE_TYPES_H

#include <stdio.h>
#include <stdlib.h>

typedef unsigned char f_byte;
#define fstr(s) ((f_byte *)s)
#define fcstr(s) ((char *)s)

typedef unsigned int f_uint;
typedef unsigned long f_ulong;

typedef int f_bool;
#define true 1
#define false 0

typedef void *f_pointer;

typedef struct byte_data {
	f_byte *data;
	size_t len;
} byte_data;

typedef struct animal_pass_pair {
  f_byte *animal_name;
  byte_data *password;
} animal_pass_pair;

typedef struct generation_item {
	long credential_id;
	//byte_data *initial_hash;
	byte_data *renewal_date;
	animal_pass_pair *generated_pairs;
	f_bool scrypt;
	f_bool argon2;
} generation_item;

typedef struct generation_log {
	int item_count;
	generation_item *items;
} generation_log;

typedef enum {
	FORGIVA_PG_SIMPLE = 1,
	FORGIVA_PG_INTERMEDIATE = 2,
	FORGIVA_PG_ADVANCED = 3
} forgiva_pg_complexity;

typedef struct benchmark_result {
	double time_spent;
	f_bool result;
} benchmark_result;

typedef struct forgiva_options {
	f_byte *host;
	f_byte *account;
	f_byte *animal;
	int character_length;
	int complexity;
	byte_data *password_hash;
	byte_data *renewal_date;
	byte_data *signature;
	f_bool use_scrypt;
	f_bool use_argon2;
	f_bool chr_lowercase;
	f_bool chr_uppercase;
	f_bool chr_numbers;
	f_bool chr_symbols;
	f_bool use_legacy;
} forgiva_options;

typedef enum {
	F_DEBUG_SIMPLE = 1,
	F_DEBUG_INTERMEDIATE = 2,
	F_DEBUG_ADVANCED = 3
} forgiva_debug_level;

typedef struct {
	f_byte *host;
	f_byte *account;
	f_byte *renewal_date;
	f_byte *master_key;
	forgiva_pg_complexity complexity;
	f_byte *animal_name;
	f_byte *expected_password_hash;
	f_byte *expected_password_hash_scrypt;
	f_byte *expected_password_hash_argon2;
} forgiva_generation_test;

typedef struct forgiva_algorithm_test {
	f_bool is_encryption_algorithm;
	f_byte *algorithm_name;
	f_byte *data_hex;
	f_byte *key_hex;
	f_byte *iv_hex;
	f_byte *target_hex;
} forgiva_algorithm_test;

forgiva_options *parse_options_from_json(byte_data *json);
f_byte          *serialize_options_to_json(forgiva_options *options);
f_byte          *serialize_result_to_json(f_byte *animal, byte_data *password);
void 			free_forgiva_options(forgiva_options *options);

#endif
