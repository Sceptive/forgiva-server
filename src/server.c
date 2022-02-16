#include "server.h"
#include "common.h"
#include "debug.h"
#include "forgiva.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "3rdparty/mongoose/mongoose.h"

static sig_atomic_t     s_received_signal = 0;


static void signal_handler(int sig_num) {
	signal(sig_num, signal_handler);
	s_received_signal = sig_num;
}


static void ev_handler(struct mg_connection *nc, 
						int ev, 
						void *ev_data,
						void *fn_data) {

	switch (ev) {
		case MG_EV_HTTP_MSG: {
			struct mg_http_message *hm = (struct mg_http_message *) ev_data;
			if (mg_http_match_uri(hm, "/generate")) {
				byte_data *body 			= f_byte_data_new_with_data(
															hm->body.ptr, 
															hm->body.len);
				forgiva_options *options 	= parse_options_from_json(body);
				if (options != NULL) {
					f_byte *rep_json = forgiva_generate_pass_as_json(options);
					if (rep_json != NULL) {
						// Send OK response and JSON result
						mg_http_reply(nc, 200, 
							"Content-Type: application/json\r\n", 
						"%s", rep_json);		
						f_free(rep_json);
					} else {
						WARNF("Invalid result");
						// In case of any problem send 503 - 
						// Service Unavailable Code.
						mg_http_reply(nc, 503, "", "", NULL);
					}
					free_forgiva_options(options);
				} else {
					mg_http_reply(nc, 503, "", "", NULL);
				}
				f_byte_data_free(body);
			} else {
				WARNF("Invalid request");
				mg_http_reply(nc, 503, "", "", NULL);
			}
			break;
		}
	}
}

void server_main(int port) {

	char s_url[64];
	struct mg_mgr mgr;
	struct mg_connection *nc;
	int i;


	sprintf(s_url,"http://0.0.0.0:%d",port);

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	mg_mgr_init(&mgr);

  	mg_http_listen(&mgr, s_url, ev_handler, NULL);  // Create HTTP listener

	OKF("Web server started on  %s\n", s_url);

	for (;s_received_signal == 0;) mg_mgr_poll(&mgr, 1000);    

	mg_mgr_free(&mgr);


}
