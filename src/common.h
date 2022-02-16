#include "types.h"

#ifndef __HAVE_COMMON_H
#define __HAVE_COMMON_H

//  Windows
#ifdef WIN32
#include <windows.h>
#include <io.h>
//  Posix/Linux
#else
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#endif

#include <ctype.h>

#include <string.h>

#ifdef WIN32
// There is no strndup in Windows environment
char *strndup(const char *s, size_t n);
#endif

#define BD_STR(BD) (BD != NULL ? BD->data : NULL)

char *concat(int count, ...);

void f_free(f_pointer pt);

f_pointer f_malloc(size_t size);

f_bool      is_byte_data_equals(byte_data *a,byte_data *b);

f_byte *f_byte_new(byte_data *);

byte_data *f_byte_data_new(size_t len);

byte_data *f_byte_data_new_with_str(const f_byte *str);
byte_data *f_byte_data_new_with_str_ex(const f_byte *str,size_t len);


byte_data *f_byte_data_new_with_data(const f_byte *data, size_t len);

byte_data *f_byte_data_dup(byte_data *data);

byte_data *f_byte_data_new_with_hex_str(const f_byte *hex_string);

byte_data *f_current_date_formatted(f_byte *format);

void f_remove_all(f_byte *str, char c);

void f_byte_data_free(byte_data *b);
int strcicmp(char const *a, char const *b);

/* utility function to convert hex character representation to their nibble (4
 * bit) values */
f_byte nibbleFromChar(f_byte c);

f_byte *f_duplicate(f_byte *);

f_byte *f_duplicate_s(f_byte *src, size_t len);

/* Convert a string of characters representing a hex buffer into a series of
 * bytes of that real value */
f_byte *to_byte(f_byte *inhex);

f_byte *bd_to_hex(byte_data *bd);

f_byte *b_to_hex(f_byte *f);

f_byte *f_byte_truncate_middle(f_byte *str, f_uint max_len);
void   f_byte_truncate_middle_ex(f_byte *_str, f_uint _str_len, f_byte *_target, f_uint _target_len);


f_byte *f_hex_dump(void *addr, int len);
void   f_hex_dump_ex(void *_addr,f_uint _addr_len,f_byte *_target);


double f_get_wall_time();

/* Returns available cpu numbers */
int f_get_cpu_cores();

void *f_itoa(int value, char *result,int base);

#endif
