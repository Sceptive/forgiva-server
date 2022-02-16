#include "common.h"
#include "debug.h"
#include "types.h"
#include <stdarg.h> // va_*
#include <stdlib.h> // calloc

#include <string.h> // strlen, strcpy

#include <time.h>

#ifdef WIN32
// There is no strndup in Windows environment
char *strndup(const char *s, size_t n) {
  char *result;
  size_t len = strlen(s);

  if (n < len)
    len = n;

  result = (char *)f_malloc(len + 1);
  if (!result)
    return 0;

  result[len] = '\0';
  return (char *)memcpy(result, s, len);
}
#endif

char *concat(int count, ...) {
  va_list ap;
  int i;

  // Find required length to store merged string
  int len = 1; // room for NULL
  va_start(ap, count);
  for (i = 0; i < count; i++)
    len += strlen(va_arg(ap, char *));
  va_end(ap);

  // Allocate memory to concat strings
  char *merged = calloc(sizeof(char), len);
  int null_pos = 0;

  // Actually concatenate strings
  va_start(ap, count);
  for (i = 0; i < count; i++) {
    char *s = va_arg(ap, char *);
    strcpy(merged + null_pos, s);

    null_pos += strlen(s);
  }
  va_end(ap);

  return merged;
}

void f_free(f_pointer pt) {
  if (pt != NULL)
    free(pt);
}

f_pointer f_malloc(size_t size) {

  f_pointer ret;
  if (!size) {
    return NULL;
  }
  ret = calloc(size, 1);
  if (ret)
    return ret;
  FATAL("Could not allocate %zu bytes", size);
}


f_byte *f_byte_new(byte_data *src) {
	return f_duplicate_s(src->data, src->len);
}

f_byte *f_duplicate_s(f_byte *src, size_t len) {
	f_byte *result;
	
	
	result = (f_byte *)f_malloc(len + 1);
	if (!result)
		return 0;
	
	result[len] = '\0';
	memcpy(result, src, len);
	return result;
	
}


f_byte *f_duplicate(f_byte *src) {
	
	return f_duplicate_s(src,strlen(fcstr(src)));

}

byte_data *f_byte_data_new(size_t len) {
  byte_data *ret = (byte_data *)f_malloc(sizeof(byte_data));
  ret->data = (f_byte *)f_malloc(len * sizeof(f_byte));
  ret->len = len;

  return ret;
}

byte_data *f_byte_data_new_with_data(const f_byte *data, size_t len) {
  byte_data *ret = f_byte_data_new(len);
  memcpy(ret->data, data, len);

  return ret;
}


byte_data *f_byte_data_new_with_str(const f_byte *str) {

  return f_byte_data_new_with_data(str, strlen(fcstr(str)));
}

byte_data *f_byte_data_dup(byte_data *data) {
  byte_data *ret = f_byte_data_new_with_data(data->data, data->len);

  return ret;
}

byte_data *f_current_date_formatted(f_byte *format) {
  // GDateTime *today = g_date_time_new_now_local();

  f_byte *text = f_malloc(100 * sizeof(f_byte));
  time_t now = time(NULL);
#ifdef WIN32
  struct tm t;
  localtime_s(&t, &now);
  strftime(text, 98, format, &t);

#else
  struct tm *t = localtime(&now);
  strftime(fcstr(text), 98, fcstr(format), t);

#endif
  text[99] = '\0';

  byte_data *ret = f_byte_data_new_with_data(text, 100);

  f_free(text);

  return ret;
}

void f_remove_all(f_byte *str, char c) {
  f_byte *pr = str, *pw = str;
  while (*pr) {
    *pw = *pr++;
    pw += (*pw != c);
  }
  *pw = '\0';
}

void f_byte_data_free(byte_data *b) {
  f_free(b->data);
  f_free(b);
}

int h_to_data(f_byte *data, const f_byte *hexstring, size_t len) {
  unsigned const char *pos = (unsigned char *)hexstring;
  char *endptr;
  size_t count = 0;

  if ((hexstring[0] == '\0') || (strlen(fcstr(hexstring)) % 2)) {
    // hexstring contains no data
    // or hexstring has an odd length
    return -1;
  }

  for (count = 0; count < len; count++) {
    char buf[5] = {'0', 'x', pos[0], pos[1], 0};
    data[count] = (f_byte)strtol(buf, &endptr, 0);
    pos += 2 * sizeof(char);

    if (endptr[0] != '\0') {
      // non-hexadecimal character encountered
      return -1;
    }
  }

  return 0;
}

byte_data *f_byte_data_new_with_hex_str(const f_byte *hex_string) {

  const size_t result_len = strlen(fcstr(hex_string)) / 2;

  f_byte *data = f_malloc(result_len * sizeof(f_byte));

  if (h_to_data(data, hex_string, result_len) == 0) {

    byte_data *ret = f_byte_data_new_with_data(data, result_len);

    f_free(data);

    return ret;
  }

  f_free(data);

  return f_byte_data_new(0);
}

int strcicmp(char const *a, char const *b) {

  for (;; a++, b++) {
    int d = tolower(*a) - tolower(*b);
    if (d != 0 || !*a)
      return d;
  }
}

/* utility function to convert hex character representation to their nibble (4
 * bit) values */
f_byte nibbleFromChar(f_byte c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return 255;
}

/* Convert a string of characters representing a hex buffer into a series of
 * bytes of that real value */
f_byte *to_byte(f_byte *inhex) {
  f_byte *retval;
  f_byte *p;
  int len, i;

  len = strlen((const char *)inhex) / 2;
  retval = malloc(len + 1);
  for (i = 0, p = (f_byte *)inhex; i < len; i++) {
    retval[i] = (nibbleFromChar(*p) << 4) | nibbleFromChar(*(p + 1));
    p += 2;
  }
  retval[len] = 0;
  return retval;
}

f_byte *b_to_hex(f_byte *f) {

  byte_data *bd = f_byte_data_new_with_str(f);

  f_byte *ret = bd_to_hex(bd);

  f_byte_data_free(bd);

  return ret;
}

f_byte *bd_to_hex(byte_data *bd) {

	f_byte hex_str[] = "0123456789abcdef";
	f_byte *ret;

	ret = (f_byte *)malloc(bd->len * 2 + 1);
	(ret)[bd->len * 2] = 0;

	if (!bd->len) {
		f_free(ret);
		return NULL;
	}

	for (f_uint i = 0; i < bd->len; i++) {
		(ret)[i * 2 + 0] = hex_str[(bd->data[i] >> 4) & 0x0F];
		(ret)[i * 2 + 1] = hex_str[(bd->data[i]) & 0x0F];
	}
	return ret;
}

void f_byte_truncate_middle_ex(f_byte *_str, f_uint _str_len, f_byte *_target, f_uint _target_len) {

  // printf("\nf_byte_truncate_middle_ex in: S: %s %d ",_str,_str_len,_target_len);
  // fflush(stdout);
  int    p_target_len = _target_len-1;

  f_bool even         = (p_target_len % 2) == 0;
  int    head_w       = (even ? (p_target_len / 2) - 1 : ((p_target_len - 1) / 2) - 1);
  int    tail_p       = _str_len - head_w;
  if (!even)
    head_w--;

  f_byte *head  = fstr(strndup(fcstr(_str), head_w));

  snprintf(fcstr(_target), p_target_len, (even ? "%s..%s" : "%s...%s"), head,
           _str + tail_p);

  f_free(head);

  _target[_target_len] = '\0';


}

f_byte *f_byte_truncate_middle(f_byte *str, f_uint max_len) {

  f_uint s_len = strlen(fcstr(str));

  if (s_len <= max_len)
#ifdef WIN32
    return _strdup(str);
#else
    return fstr(strdup(fcstr(str)));
#endif
  f_byte *truncated = f_malloc(max_len + 2);


  f_byte_truncate_middle_ex(str,s_len,truncated,max_len);

  return truncated;
}


void f_hex_dump_ex(void *_addr,f_uint _addr_len,f_byte *_target) {
  int i =0;
  unsigned char *d_addr = (unsigned char *) _addr;

  if (_addr_len <= 0) {
    return;
  }

  for (;i<_addr_len;i++) {
    unsigned char add = d_addr[i];
    
    sprintf(_target+(i*2),  "%2x", fcstr(add));
    //printf("\n%2x - %s %p",add,_target,(_target+(i*2)));
  }

  f_byte *_target_z_byte = _target+(_addr_len*2)+1;
  ((unsigned char *)_target_z_byte)[0] = '\0';

  // printf("\nT: %s",_target);
  // fflush(stdout);

}


f_byte *f_hex_dump(void *addr, int len) {
  int i;
  unsigned char *pc = (unsigned char *)addr;

  f_byte *ret = f_malloc(len * 2 + 1);

  f_hex_dump_ex(addr,len,ret);


  return ret;
}

f_bool      is_byte_data_equals(byte_data *a,byte_data *b) {

	f_bool same = (a->len == b->len);
	if (same) {
		same = strncmp(fcstr(a->data), fcstr(b->data),
				a->len) == 0;
	}
	return same;
}
void *f_itoa(int value, char *result,int base)
{
		// check that the base if valid
		if (base < 2 || base > 36) { *result = '\0'; return result; }

		char* ptr = result, *ptr1 = result, tmp_char;
		int tmp_value;

		do {
			tmp_value = value;
			value /= base;
			*ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
		} while ( value );

		// Apply negative sign
		if (tmp_value < 0) *ptr++ = '-';
		*ptr-- = '\0';
		while(ptr1 < ptr) {
			tmp_char = *ptr;
			*ptr--= *ptr1;
			*ptr1++ = tmp_char;
		}
		return result;
}


/* Returns available cpu numbers */


//  Windows
#ifdef _WIN32
#include <windows.h>
double f_get_wall_time() {
  LARGE_INTEGER time, freq;
  if (!QueryPerformanceFrequency(&freq)) {
    //  Handle error
    return 0;
  }
  if (!QueryPerformanceCounter(&time)) {
    //  Handle error
    return 0;
  }
  return (double)time.QuadPart / freq.QuadPart;
}

int f_get_cpu_cores() {
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
}

//  Posix/Linux
#else
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

double f_get_wall_time() {
	struct timeval time;
	if (gettimeofday(&time, NULL)) {
		//  Handle error
		return 0;
	}
	return (double)time.tv_sec * 1000 + (double)time.tv_usec * .001;
}

int f_get_cpu_cores() {
	return sysconf(_SC_NPROCESSORS_ONLN);
}
#endif
