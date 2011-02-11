/**
 * (c) 2000-2006 IC&S, The Netherlands
 * (c) 2008-2011 NFG, The Netherlands, paul@nfg.nl
 */

#ifndef NETWORKCONNECTOR_H
#define NETWORKCONNECTOR_H

#include "apr_network_io.h"
#include "httpd.h"

int   connection_write_bytes(apr_socket_t *, request_rec *, const char *, int);
int   connection_read_bytes(apr_socket_t *, request_rec *, char *, int);
int   connection_write_string(apr_socket_t *, request_rec *, const char *);
char *connection_read_string(apr_socket_t *, request_rec *);

#endif
