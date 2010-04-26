/** $Id: networkconnector.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */

#ifndef NETWORKCONNECTOR_H
#define NETWORKCONNECTOR_H

#include "datatypes.h"

#include "httpd.h"

#include <sys/time.h>

apr_socket_t* networkconnect (wodan_config_t *config, char* host, int port, request_rec *r, int do_ssl);

int connection_close(apr_socket_t *socket, const request_rec *r);

int connection_write_bytes(apr_socket_t *socket, const request_rec *r, const char *buffer, int buffersize);

int connection_read_bytes(apr_socket_t *socket, const request_rec *r, char *buffer, int buffersize);

int connection_write_string(apr_socket_t *socket, const request_rec *r, const char *the_string);

char *connection_read_string(apr_socket_t *socket, const request_rec *r);

int connection_flush_write_stream(apr_socket_t *socket, const request_rec *r);
#endif
