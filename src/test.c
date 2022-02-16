#include "common.h"
#include "debug.h"
#include "forgiva.h"
#include "test.h"

#include "3rdparty/argon2/argon2.h"

f_bool f_byte_data_compare(byte_data *in, byte_data *in2, f_bool ignore_case)
{

    if (in->len != in2->len)
        return false;

    for (f_uint i = 0; i < in->len; i++) {

        f_byte *a = in->data + i;
        f_byte *b = in2->data + i;

        if (ignore_case && tolower(*a) != tolower(*b)) {
            return false;
        } else if (!ignore_case && *a != *b) {
            return false;
        }
    }

    return true;
}

f_bool f_f_byte_compare_ex(f_byte *in, f_byte *in2, f_bool ignore_case,int _len)
{


    byte_data *bd1 = f_byte_data_new_with_data(in, _len);
    byte_data *bd2 = f_byte_data_new_with_data(in2, _len);

    f_bool ret = f_byte_data_compare(bd1, bd2, ignore_case);

    f_byte_data_free(bd1);
    f_byte_data_free(bd2);

    return ret;
}

f_bool f_f_byte_compare(f_byte *in, f_byte *in2, f_bool ignore_case)
{

    int l1 = strlen(fcstr(in));
    int l2 = strlen(fcstr(in2));

    if (l1 != l2)
        return false;

    return f_f_byte_compare_ex(in,in2,ignore_case,l1);
}



f_byte *duration_to_str(double ms)
{
    f_byte *ret = f_malloc(100);

    f_bool w_minute = (ms >= 60000);

    f_uint hours = (f_uint)ms / 60000 / 60;

    f_uint mins = (f_uint)ms / 60000;
    f_uint secs = ((f_uint)ms - (60000 * mins)) / 1000;
    f_uint mss = ((f_uint)ms - (60000 * mins) - (1000 * secs));

    if (w_minute) {

        snprintf(fcstr(ret), 100, "%u:%u:%u.%ums", hours, mins, secs, mss);
    } else {
        snprintf(fcstr(ret), 100, "%u.%ums", secs,
                 secs == 0 ? (int)(ms * 1000) : mss);
    }

    return ret;
}

benchmark_result benchmark(f_byte *description,
                           f_bool (*f)(forgiva_options *opts),
                           forgiva_options *opts)
{

    ACTF("Testing " cMGN "%s" cRST " ... ", description);

    benchmark_result ret = (benchmark_result) {
        .result = false, .time_spent = 0
    };

    double s_time = f_get_wall_time();
    f_bool res = (*f)(opts);

    ret.time_spent = f_get_wall_time() - s_time;
    ret.result = res;

    f_byte *duration_as_str = duration_to_str(ret.time_spent);

    if (res) {
        OKF("" cMGN "%s" cRST " --- " cGRN "SUCCESFULLY" cRST " --- (%s)",
            description, duration_as_str);
    } else {
        FATAL("" cMGN "%s" cRST " --- " cRED "FAILED" cRST " --- (%s)", 
                description,
              duration_as_str);
    }

    f_free(duration_as_str);

    return ret;
}

f_bool test_generation(forgiva_options *opts)
{

    for (int i = 0; i < FORGIVA_GENERATION_TEST_COUNT; i++) {

        forgiva_generation_test fgt = fg_tests[i];
// TODO FIX
        if (fgt.complexity <= 3) {
			
			for (int at=0;at<3;at++) {
				
            byte_data *password = f_byte_data_new_with_str(fgt.master_key);

            byte_data *p_hash = forgiva_initial_password_hash(password);

            f_byte_data_free(password);

            opts->password_hash = p_hash;
            opts->renewal_date = f_byte_data_new_with_str(fgt.renewal_date);

            opts->host = fgt.host;
			opts->use_scrypt = at == 1 ? true : false;
			opts->use_argon2 = at == 2 ? true : false;

            opts->account = fgt.account;
            opts->complexity = fgt.complexity;
            opts->animal = fgt.animal_name;
            opts->character_length = 16;

            ACTF("Testing for " cYEL "%s" cMGN "%s / %s / %s / %s  " cRST
                 "on complexity level " cGRN "%d" cRST "..." ,
				 (at == 0 ? "" : at == 1 ? "+SCRYPT " : "+ARGON2 "),
                 opts->host, opts->account, fgt.renewal_date, opts->animal, 
                opts->complexity );


            animal_pass_pair *ht = forgiva_generate_passes(opts);

            if (ht == NULL) {
                ABORT("Invalid test data or failed situation!");
            }

            int idx = -1;
            for (int ii = 0; ii < F_ANIMAL_COUNT; ii++) {
                if (strcmp(fcstr(ht[ii].animal_name), 
                    fcstr(fgt.animal_name)) == 0) {
                    idx = ii;
                }
            }

            f_byte *g_pass = f_byte_new(ht[idx].password);
            f_byte *g_pass_hash = bd_to_hex(ht[idx].password);

#ifdef FORGIVA_DEBUG
            
            forgiva_debug_n(F_DEBUG_ADVANCED, "Generated: %s", g_pass_hash);
#endif            

            if (!f_f_byte_compare_ex(g_pass_hash, at == 0 
                                    ? fgt.expected_password_hash
								  : at == 1 
                                    ? fgt.expected_password_hash_scrypt :
								  fgt.expected_password_hash_argon2, true, 
                                opts->character_length*2)) {

                FATAL( "%s %s Not match (Expected: %s) %s" ,
					(at == 0 ? "" : at == 1 ? "+SCRYPT" : "+ARGON2"),
					fgt.host,
					(at == 0 ? fgt.expected_password_hash
					 : at == 1 ? fgt.expected_password_hash_scrypt :
					 fgt.expected_password_hash_argon2), g_pass_hash);
            }

            ACTF("OK " cYEL "%s " cBLU "%s " cRST "( " cYEL "%s" cRST " )  " 
                    cGRN "(%s)" cRST,
				 (at == 0 ? "" : at == 1 ? "+SCRYPT" : "+ARGON2"),
                 g_pass, g_pass_hash, fgt.animal_name);

            f_free(g_pass_hash);
            f_free(g_pass);
            f_byte_data_free(p_hash);
            f_byte_data_free(opts->renewal_date);

            f_free(ht);
			}
        }
    }

    return true;
}

f_bool test_simple_encryptions(forgiva_options *opts)
{



    for (int i = 0; i < FORGIVA_ALG_TEST_COUNT; i++) {

        forgiva_algorithm_test fat = fa_tests[i];

        byte_data *plain_data = f_byte_data_new_with_hex_str(fat.data_hex);
        byte_data *key = f_byte_data_new_with_hex_str(fat.key_hex);
        byte_data *iv = f_byte_data_new_with_hex_str(fat.iv_hex);
        byte_data *expected = f_byte_data_new_with_hex_str(fat.target_hex);

			//OKF("%s %d",fat.algorithm_name,(1<<16));
        if (fat.is_encryption_algorithm) {

            byte_data *result =
                forgiva_crypt_ext(fcstr(fat.algorithm_name), 
                                        plain_data, key, iv);

            if (!f_byte_data_compare(expected, result, true)) {

                FATAL("%s Not match. (Expected: %s) %s", fat.algorithm_name,
                      fat.target_hex, bd_to_hex(result));
            }

            OKF("Tested %s encryption algorithm " cGRN "SUCCESSFULLY" cRST,
                fat.algorithm_name);

            f_byte_data_free(result);
		} else if (strcmp(fcstr(fat.algorithm_name),"argon2d") == 0) {
		
			f_byte *n_key = f_malloc(32);
			
			argon2d_hash_raw(2, (1<<16), 1, plain_data->data, plain_data->len,
							 key->data, key->len, n_key, 32);
			
			byte_data *argon2_key = f_byte_data_new_with_data(n_key, 32);

			if (!f_byte_data_compare(expected, argon2_key, true)) {
				
				FATAL("%s Not match %s %s", fat.algorithm_name, fat.target_hex,
					  bd_to_hex(argon2_key));
			}
			
			OKF("Tested %s algorithm " cGRN " SUCCESSFULLY " cRST,
				fat.algorithm_name);
			
			f_byte_data_free(argon2_key);
		
		}
		else {

            byte_data *hash = forgiva_hash(fcstr(fat.algorithm_name),
                                           plain_data->data, plain_data->len);

            if (!f_byte_data_compare(expected, hash, true)) {

                FATAL("%s Not match %s %s", fat.algorithm_name, fat.target_hex,
                      bd_to_hex(hash));
            }

            OKF("Tested %s hash algorithm " cGRN " SUCCESSFULLY " cRST,
                fat.algorithm_name);

            f_byte_data_free(hash);
        }

        f_byte_data_free(plain_data);
        f_byte_data_free(key);
        f_byte_data_free(iv);
        f_byte_data_free(expected);
    }

    return true;
}

f_bool forgiva_test_algorithms(forgiva_options *opts)
{

    benchmark_result res = benchmark(fstr("Simple Hash & Encryption"),
                                     &test_simple_encryptions, opts);
    benchmark_result res2 =
        benchmark(fstr("Generation of passwords"), &test_generation, opts);

    f_bool ret = res.result && res2.result;

    return ret;
}
