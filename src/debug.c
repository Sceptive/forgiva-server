#include "common.h"
#include "debug.h"
#include "forgiva.h"

#include <stdarg.h>
#include <stdio.h>

int F_MAX_DEBUG_LEVEL = F_DEBUG_SIMPLE;

FILE *F_DEBUG_FILE;

int F_MAX_BUFFER = 1024;

int F_MAX_COLUMN_TO_PRINT = 91;

void f_debug_close_file() {

	if (F_DEBUG_FILE != NULL) {
		fflush(F_DEBUG_FILE);
		fclose(F_DEBUG_FILE);
		f_free(F_DEBUG_FILE);
	}

}

void f_set_debug_file(f_byte *file_name) {
	f_debug_close_file();
#ifdef WIN32
	errno_t err;

	err = fopen_s(&F_DEBUG_FILE, (char *)file_name, "w");
	if (err != 0)
		fprintf_s(stderr, "Debug file open error: %d", err);
#else
	F_DEBUG_FILE = fopen((char *)file_name, "w");
	if (F_DEBUG_FILE == NULL)
		perror("\nDebug file open error:");
#endif
}

void f_set_debug_level(int _level) { F_MAX_DEBUG_LEVEL = _level; }

	f_byte *f_debug_date_header() {
	byte_data *f_name = f_current_date_formatted((f_byte *)"%d %m %Y %H:%M");

#ifdef WIN32
#define strdup(x) _strdup(x)
#endif

	f_byte *ret = (f_byte *)strdup((char *)f_name->data);
	f_byte_data_free(f_name);
	return ret;
}

void forgiva_debug_m(int debug_level, f_byte *description) {
#ifdef FORGIVA_DEBUG
	forgiva_debug(debug_level, description, NULL, 0, "");
#endif
}

void forgiva_debug_l(int debug_level, void *data, f_uint data_len) {
#ifdef FORGIVA_DEBUG

  forgiva_debug(debug_level, (f_byte *)"CORE", data, data_len, "");
#endif
}

void forgiva_debug_s(f_byte *description) {
#ifdef FORGIVA_DEBUG
	forgiva_debug(F_MAX_DEBUG_LEVEL, description, NULL, 0, "");
#endif
}

void forgiva_debug_n(int debug_level, const char *format, ...) {
#ifdef FORGIVA_DEBUG
	va_list ap;
	va_start(ap, format);
	v_forgiva_debug(debug_level, (f_byte *)"CORE", NULL, 0, format, ap);
	va_end(ap);
#endif
}

void forgiva_debug_bd(int debug_level, f_byte *description, byte_data *data) {
#ifdef FORGIVA_DEBUG
	forgiva_debug(debug_level, description, data->data, data->len, "");
#endif
}

void forgiva_debug_d(int debug_level, f_byte *description, void *data,
		f_uint data_len) {
#ifdef FORGIVA_DEBUG
	forgiva_debug(debug_level, description, data, data_len, "");
#endif
}

void v_forgiva_debug(int debug_level, f_byte *description, void *data,
                     f_uint data_len, const char *format, va_list args) {
#ifdef FORGIVA_DEBUG

	if (debug_level > F_MAX_DEBUG_LEVEL) {
		return;
	}

	f_byte *formatted_content = f_malloc(sizeof(f_byte) * F_MAX_BUFFER);
	vsnprintf((char *)formatted_content, F_MAX_BUFFER, format, args);
	f_byte *date = f_debug_date_header();
	f_byte *debug_line = f_malloc(sizeof(f_byte) * F_MAX_BUFFER);

	snprintf((char *)debug_line, F_MAX_BUFFER, "> %s [%s] %s", date, description,
		formatted_content);


	if (F_DEBUG_FILE != NULL) {

		fprintf(F_DEBUG_FILE, "%s\n", debug_line);
		fflush(F_DEBUG_FILE);

	}

	if (data != NULL) {

		int 	hex_len		= (data_len * 2) + 1;
		f_byte *hex_dump 	= f_malloc(sizeof(f_byte) * hex_len);

		f_hex_dump_ex(data,data_len,hex_dump);

		// printf("\ndata_len %d hex_dump : %s",data_len,hex_dump);
		// fflush(stdout);


		f_byte *truncated 	= f_malloc(sizeof(unsigned char) * F_MAX_COLUMN_TO_PRINT);

		f_byte_truncate_middle_ex(hex_dump, hex_len, truncated, F_MAX_COLUMN_TO_PRINT);


		f_byte *debug_line2 = f_malloc(sizeof(f_byte) * F_MAX_COLUMN_TO_PRINT);
		snprintf((char *)debug_line2, F_MAX_BUFFER, "[%s]:%u", truncated, data_len);
	    if (F_DEBUG_FILE) {
			fprintf(F_DEBUG_FILE, "> %s\n", debug_line2);
			fflush(F_DEBUG_FILE);
	    }
	    f_free(debug_line2);

	    f_free(truncated);

	    f_free(hex_dump);
	}


		

	if (F_DEBUG_FILE)
		fflush(F_DEBUG_FILE);

	f_free(date);
	f_free(formatted_content);
	f_free(debug_line);

#endif

}

void forgiva_debug(int debug_level, f_byte *description, void *data,
                   f_uint data_len, const char *format, ...) {
#ifdef FORGIVA_DEBUG
	va_list ap;
	va_start(ap, format);
	v_forgiva_debug(debug_level, description, data, data_len, format, ap);
	va_end(ap);
#endif
}
