/** $Id: networkconnector.c 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */
#include "datatypes.h"
#include "networkconnector.h"

#include "apr.h"
#include "httpd.h"
#include "http_log.h"

#include <unistd.h>
#include <errno.h>

int connection_write_bytes(apr_socket_t *socket,
	const request_rec *r,
	const char *buffer, int buffersize) 
{
	apr_size_t nr_bytes = (apr_size_t) buffersize;
	apr_status_t socket_status;

	socket_status = apr_socket_send(socket, buffer, &nr_bytes);
	if (socket_status == APR_TIMEUP) {
		ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_DEBUG, 0, r->server,
			"write to backend timed out");
		return -1;
	}
	if (nr_bytes < ((apr_size_t) buffersize)) { 
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				"%s:%s: error writing bytes to backend.",
				__FILE__, __func__); 
		return -1;
	}

	return (int) nr_bytes;
}

int connection_read_bytes(apr_socket_t *socket,
	const request_rec *r, char *buffer, int buffersize) 
{
	apr_size_t nr_bytes = (apr_size_t) buffersize;
	apr_status_t socket_status;

	socket_status = apr_socket_recv(socket, buffer, &nr_bytes);

	if (socket_status != APR_SUCCESS) {
		if (socket_status == APR_TIMEUP) {
			ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_DEBUG, 0, r->server,
					"read from backend timed out");
			return -1;
		}
		if ((nr_bytes != (apr_size_t) buffersize) && socket_status != APR_EOF) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
					"error reading bytes from backend, read %lu bytes, "
					"buffersize = %d, err = %d", nr_bytes, buffersize, socket_status);
			return -1;
		}
	}
	return (int) nr_bytes;
}
	  
int connection_write_string(apr_socket_t *socket,
	const request_rec *r, const char *the_string)
{
	int len = (int) strlen(the_string);
	
	return connection_write_bytes(socket, r, the_string, len);
}

char *connection_read_string(apr_socket_t *socket,
	const request_rec *r)
{
	char *buffer = (char *) apr_pcalloc(r->pool, BUFFERSIZE);
	apr_size_t index = 0;
	apr_size_t byte_read = 1;
	int end_of_line = 0;
	
	while(index < BUFFERSIZE && !end_of_line) {
		apr_status_t socket_status;
		socket_status = apr_socket_recv(socket, &(buffer[index]), 
			&byte_read);
		if (socket_status == APR_TIMEUP) {
			apr_interval_time_t timeout;
			apr_socket_timeout_get(socket, &timeout);
			ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_DEBUG, 0, r->server,
				"read from backend connection timed out, timeout = %ld", timeout);
				
			return NULL;
		}
		if (socket_status == APR_EOF || buffer[index] == '\n')
			end_of_line = 1;
		index += 1;
		
	 	if (byte_read != 1) {
	     	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
    		 		"%s,%s: Error reading string from backend", 
     			__FILE__, __func__);
     		return NULL;
	 	}
     }
     
     return buffer;
}

