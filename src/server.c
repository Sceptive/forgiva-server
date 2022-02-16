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


static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
	(void) nc;
	(void) ev_data;

	switch (ev) {
		case MG_EV_HTTP_REQUEST: {
			struct http_message *hm = (struct http_message *) ev_data;
			if (mg_vcmp(&hm->uri, "/generate") == 0) {
				byte_data *body = f_byte_data_new_with_data(hm->body.p, 
															hm->body.len);
				forgiva_options *options = parse_options_from_json(body);
				if (options != NULL) {
					f_byte *rep_json = forgiva_generate_pass_as_json(options);
					if (rep_json != NULL) {
						// Send OK response and JSON result
						mg_send_head(nc, 200, 
									strlen(rep_json), 
									"Content-Type: text/plain");
						mg_printf(nc, "%s", rep_json);
						f_free(rep_json);
					} else {
						WARNF("Invalid result");
						// In case of any problem send 503 - 
						// Service Unavailable Code.
						mg_send_head(nc, 503, 0, NULL);
					}
					free_forgiva_options(options);
				} else {
					mg_send_head(nc, 503, 0, NULL);
				}
				f_byte_data_free(body);
			} else {
				WARNF("Invalid request");
				mg_send_head(nc, 503, 0, NULL);
			}
			break;
		}
		case MG_EV_CLOSE: {
			if (nc->user_data) nc->user_data = NULL;
		}
	}
}

void server_main(int port) {

	char s_http_port[6];
	f_itoa(port,s_http_port,10);
	struct mg_mgr mgr;
	struct mg_connection *nc;
	int i;


	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	mg_mgr_init(&mgr, NULL);

	nc = mg_bind(&mgr, s_http_port, ev_handler);
	if (nc == NULL) {
		FATAL("Failed to bind web server.");
	}

	mg_set_protocol_http_websocket(nc);



	OKF("Web server started on port %s\n", s_http_port);
	while (s_received_signal == 0) {
		mg_mgr_poll(&mgr, 200);
	}

	mg_mgr_free(&mgr);


}
