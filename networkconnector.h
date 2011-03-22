/**
 * (c) 2000-2006 IC&S, The Netherlands
 * (c) 2008-2011 NFG, The Netherlands, paul@nfg.nl
 */

#ifndef NETWORKCONNECTOR_H
#define NETWORKCONNECTOR_H

#include "datatypes.h"

int connection_write_bytes(apr_socket_t *socket, request_rec *r, const char *buffer, int buffersize);

int connection_read_bytes(apr_socket_t *socket, request_rec *r, char *buffer, int buffersize);

int connection_write_string(apr_socket_t *socket, request_rec *r, const char *the_string);

char *connection_read_string(apr_socket_t *socket, request_rec *r, int *status);

#endif
