#include "types.h"
#include "3rdparty/parson/parson.h"
#include "common.h"
#include "debug.h"

byte_data *json_get_string_as_bd(const JSON_Object *root_object, 
						const f_byte *key) {

	const char *value = json_object_get_string(root_object,key);
	if (value != NULL) {
		size_t s_len = strlen(value);
		byte_data *ret = f_byte_data_new_with_data(value,s_len+1);
		ret->data[s_len] = '\0';
		return ret;
	}
	return NULL;
}

f_byte *serialize_result_to_json(f_byte *animal,
	byte_data *password) {
	JSON_Value *root_value = json_value_init_object();
	JSON_Object *root_object = json_value_get_object(root_value);
	char *serialized_string = NULL;
	f_byte *password_hex = bd_to_hex(password);
	// Setting animal and password pair
	json_object_set_string(root_object,"animal",animal);
	json_object_set_string(root_object,"password",password_hex);
	// Serializing
	serialized_string = json_serialize_to_string_pretty(root_value);
	f_byte *ret = f_duplicate((f_byte *) serialized_string);
	// Cleanup
	json_free_serialized_string(serialized_string);
	json_value_free(root_value);
	f_free(password_hex);

	return ret;
}

/*
	Parses JSON representation of forgiva_options to the object.

	{
		host: "test.com",
		account: "administrator",
		animal: "Spider",
		character_length: 16,
		complexity: 1,
		is_lowercase: true,
		is_uppercase: true,
		is_symbols: true,
		is_number: true,
		password_hash: "EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4
						940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD
						8E6F57F50028A8FF",
		renewal_data: "",
		signature: "",
		legacy_mode: false

	}

*/
f_byte *serialize_options_to_json(forgiva_options *options) {
	JSON_Value *root_value = json_value_init_object();
	JSON_Object *root_object = json_value_get_object(root_value);
	char *serialized_string = NULL;

	json_object_set_string(root_object,"host",options->host);
	json_object_set_string(root_object,"account",options->account);
	json_object_set_string(root_object,"animal",options->animal);
	json_object_set_number(root_object,"character_length",
									options->character_length);
	json_object_set_number(root_object,"complexity",options->complexity);
	json_object_set_boolean(root_object,"is_lowercase",options->chr_lowercase);
	json_object_set_boolean(root_object,"is_uppercase",options->chr_uppercase);
	json_object_set_boolean(root_object,"is_symbols",options->chr_symbols);
	json_object_set_boolean(root_object,"is_numbers",options->chr_numbers);
	json_object_set_string(root_object,"password_hash",
									BD_STR(options->password_hash));
	json_object_set_string(root_object,"renewal_date",
									BD_STR(options->renewal_date));
	json_object_set_string(root_object,"signature",
									BD_STR(options->signature));
	json_object_set_boolean(root_object,"legacy_mode",options->use_legacy);

	serialized_string = json_serialize_to_string_pretty(root_value);
	f_byte *ret = f_duplicate((f_byte *) serialized_string);
	json_free_serialized_string(serialized_string);
	json_value_free(root_value);

	return ret;
}

forgiva_options *parse_options_from_json(byte_data *json) {
	JSON_Value *root_value;

	root_value = json_parse_string((const char *) json->data);
	if (json_value_get_type(root_value) != JSONObject) {
		return NULL;
	}

	JSON_Object *root_object = json_value_get_object(root_value);

	struct forgiva_options *ret;
	ret = f_malloc(sizeof(forgiva_options));

	f_byte *host 	= (f_byte *)json_object_get_string(root_object,"host");
	f_byte *account = (f_byte *)json_object_get_string(root_object,"account");
	f_byte *animal 	= (f_byte *)json_object_get_string(root_object,"animal");
	

	ret->host               = host == NULL ? NULL : f_duplicate(host);
	ret->account            = account == NULL ? NULL : f_duplicate(account);
	ret->animal             = animal == NULL ? NULL : f_duplicate(animal);
	ret->character_length   = json_object_get_number(root_object, 
													"character_length");
	ret->complexity         = json_object_get_number(root_object, 
													"complexity");
	ret->chr_lowercase      = json_object_get_boolean(root_object, 
													"is_lowercase");
	ret->chr_uppercase      = json_object_get_boolean(root_object, 
													"is_uppercase");
	ret->chr_symbols        = json_object_get_boolean(root_object, 
													"is_symbols");
	ret->chr_numbers        = json_object_get_boolean(root_object, 
													"is_number");
	ret->password_hash      = json_get_string_as_bd(root_object, 
													"password_hash");
	ret->renewal_date       = json_get_string_as_bd(root_object, 
													"renewal_date");
	ret->signature          = json_get_string_as_bd(root_object, 
													"signature");
	ret->use_legacy			= json_object_get_boolean(root_object, 
													"legacy_mode");

	json_value_free(root_value);

	return ret;
}


void free_forgiva_options(forgiva_options *options) {
	f_free(options->host);
	f_free(options->account);
	f_free(options->animal);
	if (options->password_hash != NULL)
	f_byte_data_free(options->password_hash);
	if (options->renewal_date != NULL)
	f_byte_data_free(options->renewal_date);
	if (options->signature != NULL)
	f_byte_data_free(options->signature);
	f_free(options);
}