
#include "common.h"
#include "debug.h"
#include "forgiva.h"
#include "test.h"
#include "types.h"
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include "server.h"


const char *f_fish =
	cBLU "\n      .-\" L_  " cCYA "  FORGIVA Server\n " cBLU ";`, /   ( o\\  " 
	cBLU
	" The new-age password manager.\n" cBLU " \\  ;    `, /  \n"
	" ;_/\"`.__.-\" \n\n" cRST;

static forgiva_options options;

int main(int argc, char *argv[]) {


#ifdef FORGIVA_DEBUG

	  F_MAX_DEBUG_LEVEL = F_DEBUG_ADVANCED ;

      byte_data *f_name =
          f_current_date_formatted(fstr("debug_%Y_%m_%d_%H_%M_%S.log"));

      printf("\nDebug file: %s\n", f_name->data);
      f_set_debug_file(f_name->data);
      f_byte_data_free(f_name);

#endif

	f_bool  test_algorithms = false;
	f_bool  use_stdin       = false;
	int     opt;

	const int   default_port          = 3000;
	int         port = default_port;

	while ((opt = getopt(argc,argv,"tp:s")) != -1) {
		switch (opt) {
			case 't': test_algorithms = true; break;
			case 's': use_stdin = true; break;
			case 'p': port = atoi(optarg); break;
			default:
				printf("%s", f_fish);
				printf("Usage: %s [-ts] [-p port]\n",argv[0]);
				printf("\t-t\tTest algorithms.\n");
				printf("\t-s\tUse stdin JSON rather than web server.\n");
				printf("\t-p <port>\tUse port number to bind on web server. "
						"Default: %d\n",default_port);
				exit(0);
		}
	}

	if (!use_stdin) {
		printf("%s", f_fish);
	}

	if (port <= 0) {
		WARNF("Invalid port specified. Using %d anyway.", default_port);
		port = default_port;
	}


#ifdef WIN32
#define strdup(x) _strdup(x)
#endif // WIN32


	if (test_algorithms) {
		options.use_legacy = true;
		forgiva_test_algorithms(&options);
		exit(0);
	}




	if (use_stdin) {
		const int MAX_BUF = 8192;
		f_byte *json = f_malloc(MAX_BUF);
		int idx = 0;
		int c;
		while (( c = fgetc(stdin)) != EOF) {
			json[idx] = c;
			idx++;
			if (idx > 8190) {
				FATAL("Input cannot be bigger then %d",MAX_BUF);
			}
		}

		byte_data *json_bd 			= f_byte_data_new_with_data(json,idx);
		forgiva_options *options	= parse_options_from_json(json_bd);
		if (options == NULL) {
			FATAL("Failed to parse input JSON.");
		}
		f_byte *result = forgiva_generate_pass_as_json(options);

		if (result != NULL) {
			fprintf(stdout, "%s\n", result);
			fflush(stdout);
			f_free(result);

		} else {
			FATAL("Failed to generate result");
		}
		f_byte_data_free(json_bd);
		f_free(json);
		free_forgiva_options(options);



	} else {
		ACTF("Launching web server at port: %d  ...", port );
		server_main(port);
	}

	return 0;
}
