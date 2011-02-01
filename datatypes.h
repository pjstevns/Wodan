/** $Id: datatypes.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */
#ifndef _DATATYPES_H_
#define _DATATYPES_H_


#define MAX_CACHE_PATH_SIZE 1024
#define DEFAULT_CACHEDIR_LEVELS 2
#define MAX_CACHEDIR_LEVELS 8
#define MAX_BACKEND_TIMEOUT_SEC 59

/** Maximum cache timeout in seconds. Max timeout is 365 days (as if
 * you'd ever want to use that long a timeout) */ 
#define MAX_CACHE_TIMEOUT 60 * 60 * 24 * 365

#define BUFFERSIZE 2048

#define DEFAULT_CACHETIME 3600

#ifdef __GNUC__
#define UNUSED __attribute__((__unused__))
#define PRINTF_ARGS(X, Y) __attribute__((format(printf, X, Y)))
#else
#define UNUSED
#define PRINTF_ARGS(X, Y)
#endif

#include "httpd.h"
#include "apr_network_io.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_strmatch.h"
#include "apr_version.h"

#define DEBUG(fmt...) \
	wodan_trace(r, APLOG_NOERRNO|APLOG_DEBUG, __FILE__, __LINE__, __func__, fmt)

#define ERROR(fmt...) \
	wodan_trace(r, APLOG_ERR, __FILE__, __LINE__, __func__, fmt)


/**
 * Structure that contains the config elements of wodan
 */
typedef struct wodan_config {
	unsigned is_cachedir_set; /* 1 if the cache dir is set */
	char cachedir[MAX_CACHE_PATH_SIZE + 1];/* The dir where cache files 
					    should be stored */
	unsigned run_on_cache; /* 1 if RunOnCache is set. This will make sure
				  that the backend is never contacted, which
				  is useful if there is scheduled downtime on
				  the backend */
	unsigned cache_404s; /* Cache 404s as well or not? */
	apr_interval_time_t backend_timeout; /* timeout for the backend 
					 connection. If a connection has not 
					 been made within this time, the 
					 backend is assumed to be down */
	apr_array_header_t *proxy_passes;
	apr_array_header_t *proxy_passes_reverse;
	apr_array_header_t *default_cachetimes;
	apr_array_header_t *default_cachetimes_regex;
	apr_array_header_t *default_cachetimes_header;
	apr_array_header_t *hash_headers;
	apr_array_header_t *hash_headers_match;
	
	int cachedir_levels;
} wodan_config_t;
/**
 * Structure containing info about a ReverseProxyPass directive
 */
typedef struct wodan_proxy_destination {
	const char *path;
	const char *url;
} wodan_proxy_destination_t;

/**
 * Structure containing info about a ReverseProxyPassReverse directive
 */
typedef struct wodan_proxy_alias {
	const char *path;
	const char *alias;
} wodan_proxy_alias_t;

/**
 * Structure containing info about a DefaultCacheTime directive
 */
typedef struct wodan_default_cachetime {
	const char *path;	
	apr_int32_t cachetime;
} wodan_default_cachetime_t;

/**
 * Structure containing info for the DefaultCacheTimeRegex directive
 */
typedef struct wodan_default_cachetime_regex {
	ap_regex_t *uri_pattern;
	apr_int32_t cachetime;
} wodan_default_cachetime_regex_t;

/**
 * Structure containing info for the DefaultCacheTimeHeader directive
 */
typedef struct wodan_default_cachetime_header {
	const char *header;
	ap_regex_t *header_value_pattern;
	apr_int32_t cachetime;
} wodan_default_cachetime_header_t;

/**
 * Structure containing info for the WodanHashHeaderMatch directive
 */
typedef struct wodan_hash_header_match {
	const char *header;
	ap_regex_t *regex;
	const char *pattern;
} wodan_hash_header_match_t;

/**
 * Structure representing an httpresponse
 */
typedef struct httpresponse {
	char* content_type;//The content type of the data
	apr_table_t* headers;//A table containing the headers
	int response;//The response code
} httpresponse_t;

typedef struct wodan_cache_state {
	apr_time_t cache_file_time;
	char *cachefilename;
	wodan_config_t *config;
	request_rec *r;
	httpresponse_t *httpresponse;
} cache_state_t;


#endif //_DATATYPES_H_
