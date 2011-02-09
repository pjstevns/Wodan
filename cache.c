/*
 * (c) 2000-2006 IC&S, The Netherlands
 * (c) 2008-2011, NFG, The Netherlands, paul@nfg.nl
 */

#include <sys/stat.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "cache.h"
#include "datatypes.h"
#include "util.h"
#include "networkconnector.h"

#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "apr.h"
#include "apr_date.h"
#include "apr_sha1.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "apr_lib.h"

#define MAX_CACHEFILE_PATH_LENGTH 512

#define T CacheState_T
typedef enum {
	WODAN_CACHE_PRESENT,        /** present and fresh */
	WODAN_CACHE_EXPIRED,/** present but expired */
	WODAN_CACHE_MISSING,     /** not present */
	WODAN_CACHE_NOCACHE,   /** cannot be cached */
	WODAN_CACHE_404              /** cached 404 */
} WodanCacheStatus_t;


/**
 * Structure representing an httpresponse
 */
typedef struct {
	char* content_type;//The content type of the data
	apr_table_t* headers;//A table containing the headers
	int response;//The response code
} Response_T;

typedef struct {
	char *url;
	int ttl;
	apr_time_t expire;
	int status;
} CacheHeader_T;

struct T {
	WodanCacheStatus_t status;
	apr_time_t mtime;
	int interval;
	char expire_time[APR_RFC822_DATE_LEN];
	char *cachefilename;
	wodan_config_t *config;
	request_rec *r;
	Response_T *R;
};


void ap_reverseproxy_clear_connection(apr_pool_t *, apr_table_t *);
/**
 * \brief check if the CacheDir directive is set
 * \param config the server configuration
 * \return 
 *     - 0 if not set
 *     - 1 if set
 */
static inline int is_cachedir_set(T C)
{
	return C->config->is_cachedir_set?1:0;
}
/**
 * Return whether the http result code is cacheable
 * @param httpcode The http code to check
 * @param cache404s Specifies if 404s are treated as cacheable
 * @retval 1 if return code is cachable
 * @retval 0 if return code is not cachable
 */
static inline int is_response_cacheable (int httpcode, int cache404s)
{
	if ( cache404s && (httpcode == 404)) return 1;
	if ( httpcode == 304 ) return 0;
	if (ap_is_HTTP_SUCCESS(httpcode)) return 1;
	if (ap_is_HTTP_REDIRECT(httpcode)) return 1;
	return 0;
}

/**
 * return the name of the (nested) subdirectory used for
 * the cache file. The name of the directory is determined
 * by the name of the cache file and the number of levels
 * the directory has to be nested. A nesting depth of 
 * 2 and a cachefile of the name "abcdef" will result in
 * a name like: "a/b/" for the directory. The nr parameter
 * determines which part of the nested subdirectory will
 * be returned, counting from 0. In the above example, if
 * nr is 0, 'a' will be returned.
 * @param r request record
 * @param config the wodan configuration
 * @param cachefilename name of cachefile
 * @param nr which part of the complete directory to return.
 */
static char *get_cache_file_subdir(T C, char *cachefilename, int nr)
{
	int count;
	char *ptr;
	char *buffer;
	wodan_config_t *config = C->config;
	request_rec *r = C->r;

	buffer = apr_pstrdup(r->pool, cachefilename);

	/* We count back (from the end of the path) just enough parts 
	   to get the desired subdir */
	count = config->cachedir_levels - nr;
	ptr = buffer + (int) strlen(buffer);

	while ( ( count > 0 ) && ( ptr > buffer ) ) {
		if ( *ptr == '/' ) {
			*ptr = '\0';
			count--;
		}
		ptr--;
	}

	return buffer;
}

/**
 * return the name of the cachefile
 * @param config the wodan configuration
 * @param r request record
 * @param[out] filename will hold the filename
 * @retval 0 on error
 * @retval 1 on success 
 */
static char * sha1_to_hex(request_rec *r, const unsigned char *sha1)
{
	static const char hex[] = "0123456789abcdef";
	char buffer[50], *buf = buffer;
	int i;

	for (i = 0; i < 20; i++) {
		unsigned int val = *sha1++;
		*buf++ = hex[val >> 4];
		*buf++ = hex[val & 0xf];
	}
	*buf = '\0';

	return apr_pstrdup(r->pool, buffer);
}

static int cache_filename(T C, char **filename)
{
	unsigned char digest[APR_SHA1_DIGESTSIZE];
	char dir[MAX_CACHEFILE_PATH_LENGTH + 1];
	char *checksum;
	char *ptr;
	int i;
	request_rec *r = C->r;
	struct apr_sha1_ctx_t sha;

	apr_array_header_t *headers;

	apr_sha1_init(&sha);
	apr_sha1_update(&sha, C->r->unparsed_uri, strlen(C->r->unparsed_uri));

	/* handle WodanHashHeader directives */
	headers = C->config->hash_headers;
        if (headers) {
                int i = 0;
                for(i = 0; i < headers->nelts; i++) {
			const char *key = ((const char **)headers->elts)[i];
			const char *value = apr_table_get(C->r->headers_in, key);

			if (value) {
				DEBUG("Found header for hash [%s: %s]", key, value);
				apr_sha1_update(&sha, value, strlen(value));
			}
                }
        }

	/* handle WodanHashHeaderMatch directives */
	headers = C->config->hash_headers_match;
        if (headers) {
                int i = 0;
		wodan_hash_header_match_t *match = (wodan_hash_header_match_t *)headers->elts;
                for(i = 0; i < headers->nelts; i++) {
			const char *key = match[i].header;
			ap_regex_t *exp = match[i].regex;
			const char *rep = match[i].pattern;

			DEBUG("Lookup header [%s]", match[i].header);

			const char *val, *value = apr_table_get(C->r->headers_in, key);

			if (value) {
				val = NULL;
				apr_size_t nmatch = 5;
				ap_regmatch_t pmatch[5];
				if (ap_regexec(exp, value, nmatch, pmatch, 0) == 0) {
					if (rep)
						val = ap_pregsub(r->pool, rep, value, nmatch , pmatch);
					else
						val = value;

					if (val) {
						DEBUG("Found header match [%s: %s] -> use [%s]", key, value, val);
						apr_sha1_update(&sha, val, strlen(val));
					}
				} else {
					DEBUG("No match on [%s: %s]", key, value);
				}
					
			}
                }
        }


	apr_sha1_final(digest, &sha);

	checksum = sha1_to_hex(C->r, digest);

	/* If cachedir + subdirs + checksum don't fit in buffer, 
	 * we have a problem */
	if (strlen(C->config->cachedir) > 
	     (MAX_CACHEFILE_PATH_LENGTH - 32 - (2 * MAX_CACHEDIR_LEVELS))) {
		ERROR("Cachefile pathname doesn't fit into buffer.");
		*filename = NULL;
		return 0;
	}

	apr_cpystrn(dir, C->config->cachedir, MAX_CACHEFILE_PATH_LENGTH + 1);
	ptr = &dir[0] + (int) strlen(dir);
	
	if (*ptr == '/')
		ptr--;

	for (i = 0; i < C->config->cachedir_levels; i++) {
		ptr[0] = '/';
		ptr[1] = checksum[i];
		ptr += 2;
	}
	*ptr = '\0';

	*filename = ap_make_full_path(C->r->pool, dir, checksum);

	DEBUG("%s", *filename);

	return 1;
}

static float get_random_number(int max)
{
	assert(max > 0);
	unsigned int seed = (unsigned int)(apr_time_now());
	int r = rand_r(&seed) & max;
	if (r)
		return (float)1/(float)r;
	return (float)r;
}
/* 
 * Copy key/data pair of overlay only if that key is not set for base.
 *
 * Note that there exists no apr method exactly like this one.
 */
static void wodan_table_add_when_empty(T C)
{
	apr_table_t *base = C->R->headers;
	apr_table_t *overlay = C->r->headers_out;

	const apr_array_header_t *overlay_array = apr_table_elts(overlay);
	apr_table_entry_t *elts = (apr_table_entry_t *)overlay_array->elts;
	int i;
	
	for (i = 0; i < overlay_array->nelts; ++i) 
		if(!apr_table_get(base, elts[i].key))
			apr_table_add(base, elts[i].key, elts[i].val);
}

static const char* wodan_location_reverse_map(wodan_proxy_alias_t* alias, const char *url,
	request_rec *r)
{
	int url_len;
	int alias_len;
	
	url_len = strlen(url);
	alias_len = strlen(alias->alias);
	DEBUG("reverse map [%s] -> [%s]", url, alias->alias);
	if (url_len >= alias_len && strncmp(alias->alias, url, alias_len) == 0) {
		char *constructed_url, *result;
		constructed_url = apr_pstrcat(r->pool, alias->path, &url[alias_len], NULL);
		result = ap_construct_url(r->pool, constructed_url, r);
		DEBUG("result [%s]", result);
		return (const char *)result;
	}
	else return url;

}

static wodan_proxy_alias_t* alias_longest_match(wodan_config_t *config, char *uri)
{
	wodan_proxy_alias_t *longest, *list;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan_proxy_alias_t *) config->proxy_passes_reverse->elts;
	for(i=0; i < config->proxy_passes_reverse->nelts; i++)
	{
		int l = (int) strlen(list[i].path);

		if(l > length && strncmp(list[i].path, uri, l) == 0)
		{
			longest = &list[i];
			length = l;
		}
	}
	return longest;
}

static void apply_proxy_pass_reverse(T C)
{
	const char* url;
	wodan_proxy_alias_t *alias;
	wodan_config_t *config = C->config;
	apr_table_t* headers = C->R->headers;
	request_rec *r = C->r;

	alias = alias_longest_match(config, r->uri);

	if(alias == NULL)
		return;
	
	if((url = apr_table_get(headers, "Location")) != NULL)
		apr_table_set(headers, "Location", wodan_location_reverse_map(alias, url, r));

	if((url = apr_table_get(headers, "URI")) != NULL)
		apr_table_set(headers, "URI", wodan_location_reverse_map(alias, url, r));

	if((url = apr_table_get(headers, "Content-Location")) != NULL)
		apr_table_set(headers, "Content-Location", wodan_location_reverse_map(alias, url, r));
}



void adjust_headers_for_sending(T C)
{
	/* do more adjustments to the headers. This used to be in 
	   mod_reverseproxy.c */
	apr_table_unset(C->R->headers, "X-Wodan");

	wodan_table_add_when_empty(C);
	apply_proxy_pass_reverse(C);
	
	C->r->headers_out = C->R->headers;
	C->r->content_type = apr_table_get(C->R->headers, "Content-Type");
	C->r->status = C->R->response;
}

T cache_new(request_rec *r, module *wodan_module)
{
	T C;
	C = apr_pcalloc(r->pool, sizeof(*C));
	C->config = (wodan_config_t *)ap_get_module_config(r->server->module_config, wodan_module);
	C->R = apr_pcalloc(r->pool, sizeof(Response_T));
	C->R->headers = apr_table_make(r->pool, 0);
	C->r = r;
	return C;
}

void cache_mtime(T C)
{
	apr_finfo_t finfo;
	apr_stat(&finfo, C->cachefilename, APR_FINFO_MTIME, C->r->pool);
	C->mtime = finfo.mtime;
}

int cache_status(T C)
{
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int status;
	long int ttl;
	wodan_config_t *config = C->config;
	request_rec *r = C->r;
	char ** cachefilename = &(C->cachefilename);
	float rand;
	apr_time_t cachefile_expire_time;


	if(r->method_number != M_GET && !r->header_only) {
		C->status = WODAN_CACHE_NOCACHE;
		return C->status;
	}

	// if the CacheDir directive is not set, we cannot read from cache
	if (! is_cachedir_set(C)) {
		C->status = WODAN_CACHE_MISSING;
		return C->status;
	}

	if (! cache_filename(C, cachefilename)) {
		C->status = WODAN_CACHE_NOCACHE;
		return C->status;
	}

	if (apr_file_open(&cachefile, *cachefilename, APR_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		C->status = WODAN_CACHE_MISSING;
		return C->status;
	}

	/* Read url field, but we don't do anything with it */
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) != APR_SUCCESS) {
		apr_file_close(cachefile);
		C->status = WODAN_CACHE_MISSING;
		return C->status;
	}

	/* read expire interval field */
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) != APR_SUCCESS) {
		apr_file_close(cachefile);
		C->status = WODAN_CACHE_MISSING;
		return C->status;
	}
	C->interval = atoi(buffer);

	/* expire field */
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) != APR_SUCCESS) {
		apr_file_close(cachefile);
		C->status = WODAN_CACHE_MISSING;
		return C->status;
	}

	/* Parses a date in RFC 822  */
	if ((cachefile_expire_time = apr_date_parse_http(buffer)) == APR_DATE_BAD) {
		ERROR("Cachefile date not parsable. Returning \"Expired status\"");
		C->status = WODAN_CACHE_EXPIRED;
		return C->status;
	}

	cache_mtime(C);

	ttl =  ((long int) cachefile_expire_time - (long int) r->request_time)/1000000;
	ttl = ttl<0?0:ttl;

	DEBUG("%d %ld", C->interval, ttl);

	if(ttl == 0) {
		apr_file_close(cachefile);
		C->status = WODAN_CACHE_EXPIRED;
		return C->status;
	}

	// get a random number 
	rand = get_random_number(100000);

	if (ttl < (C->interval/10)) {
		if (rand <= 0.001) {
			apr_file_close(cachefile);
			C->status = WODAN_CACHE_EXPIRED;
			return C->status;
		}
	} else if (ttl < (C->interval/5)) {
		if (rand <= 0.0001) {
			apr_file_close(cachefile);
			C->status = WODAN_CACHE_EXPIRED;
			return C->status;
		}
	} else if (ttl < (C->interval/4)) {
		if (rand <= 0.00005) {
			apr_file_close(cachefile);
			C->status = WODAN_CACHE_EXPIRED;
			return C->status;
		}
	}

	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		status = atoi(buffer);
		if (status == HTTP_NOT_FOUND) {
			if (config->cache_404s) {
				DEBUG("cache status [404] while Cache404s is On");
				apr_file_close(cachefile);
				C->status = WODAN_CACHE_404;
				return C->status;
			}
			DEBUG("unlink cached [404] while Cache404s is Off");
			const char *fname;
			apr_file_name_get(&fname, cachefile);
			apr_file_remove(fname, r->pool);
			apr_file_close(cachefile);
			C->status = WODAN_CACHE_MISSING;
			return C->status;
		}
	}
	while (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		if (strncasecmp(buffer, "Last-Modified", 13) == 0) {
			if (strlen(buffer) > 40) {
				apr_time_t last_modified;
				if ((last_modified = apr_date_parse_http(buffer+14)))
					C->mtime = last_modified;
			}
			break;
		}

		if ((strncmp(buffer, "\r\n", 2) == 0) || (strncmp(buffer,"\n",1) == 0))
			break;
	}

	apr_file_close(cachefile);
	C->status = WODAN_CACHE_PRESENT;
	return C->status;
}

int cache_read(T C)
{
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int write_error;
	int content_length = 0;
	int body_bytes_written = 0;
	
	request_rec *r = C->r;
	char **cachefilename = &(C->cachefilename);

	// 304 short circuit
	const char *ifmodsince;
	if ((ifmodsince = apr_table_get(r->headers_in, "If-Modified-Since"))) {
		apr_time_t if_modified_since;
		if ((if_modified_since = apr_date_parse_http(ifmodsince))) {
			if (C->mtime <= if_modified_since) {
				C->R->response = HTTP_NOT_MODIFIED;
				return OK;
			}
		}
	}

	apr_file_open(&cachefile, *cachefilename, APR_READ, APR_OS_DEFAULT, r->pool);
	/* Read url field, but we don't do anything with it */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* same for expire interval field */
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		int interval_time;
		if (! (interval_time = atoi(buffer))) {
			ERROR("unlink cachefile with interval_time 0");
			const char *fname;
			apr_file_name_get(&fname, cachefile);
			apr_file_remove(fname, r->pool);
			apr_file_close(cachefile);
			C->status = WODAN_CACHE_MISSING;
			return C->status;
		}
	}

	/* store expire field */
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS)
		apr_cpystrn(C->expire_time, buffer, sizeof(C->expire_time));

	if(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		C->R->response = atoi(buffer);
	} else {
		//Remove file and return 0
		apr_file_close(cachefile);
		apr_file_remove(*cachefilename, r->pool);
		return 0;
	}

	// read the headers
	while(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		int counter = 0;
		char* key;
		char* bufferpointer;
		if(strcasecmp(buffer, CRLF) == 0)
			break;
		bufferpointer = &buffer[0];
		key = ap_getword(r->pool, (const char**) &bufferpointer, ':');
		bufferpointer = util_skipspaces(bufferpointer);
		while(bufferpointer[counter]) {
			if(bufferpointer[counter] == CR || bufferpointer[counter] == LF ) {
				bufferpointer[counter] = '\0';
				break;
			}
			counter++;
		}
		apr_table_add(C->R->headers, key, bufferpointer);
		if (strncasecmp(key, "Content-Length", 14) == 0)
			content_length = atoi(bufferpointer);
	}

	// fixup and dispatch the headers
	adjust_headers_for_sending(C);

	if(r->header_only)
		return 1;

	// read the actual response body and dispatch it to the client
	write_error = 0;
	while(!apr_file_eof(cachefile) && !write_error) {
		apr_size_t bytes_read;
		int bytes_written;

		apr_file_read_full(cachefile, buffer, BUFFERSIZE, &bytes_read);

		bytes_written = ap_rwrite(buffer, bytes_read, r);
		body_bytes_written += bytes_written;
		if (((int) bytes_read != bytes_written) || bytes_written == -1) {
			write_error = 1;
		}
		if(bytes_read < BUFFERSIZE)
			break;
	}

	ap_rflush(r);

	/* TODO add error checking for file reading */
	if (write_error) {
		const char *user_agent;

		user_agent = apr_table_get(r->headers_in, "User-Agent");
		if (user_agent == NULL) 
			user_agent = "unknown";
		ERROR("error writing to socket. "
				"Bytes written/Body length = %d/%d, "
				"User-Agent: %s", body_bytes_written, content_length, user_agent);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return 1;
}

int cache_handler(T C)
{
	// see if the request can be handled from the cache.
	WodanCacheStatus_t status = cache_status(C);

	switch (status) {
		case WODAN_CACHE_404:
		case WODAN_CACHE_PRESENT:
			cache_read(C);
			break;

		case WODAN_CACHE_EXPIRED:
		case WODAN_CACHE_MISSING:
		case WODAN_CACHE_NOCACHE:
			//Get the httpresponse from remote server	
			if ((cache_update(C) == DECLINED))
				return DECLINED;
			break;
	}

	return C->r->status = C->R->response;
}

static apr_time_t parse_xwodan_expire(request_rec *r,
				  char *xwodan, int cachetime, 
				  int *cachetime_interval) 
{
	apr_time_t expire_time;
	char *expires, *c;

	*cachetime_interval = 0;
	expires = util_skipspaces(&xwodan[6]);

	DEBUG("Parsing expire header: \"%s\"", expires);
	c = expires;
	if ( *c >= '0' && *c <= '9' ) {
		DEBUG("Expire header is numeric. Assuming addition of interval to current time.");
		*cachetime_interval = util_timestring_to_seconds(c);
		DEBUG("cachetime_interval = %d", *cachetime_interval);
		expire_time = r->request_time + apr_time_from_sec(*cachetime_interval);
	} else {
		if (! (expire_time = apr_date_parse_http(expires))) {
			DEBUG("Invalid expire time, using default cache time");
			expire_time = r->request_time + apr_time_from_sec(cachetime);
		}	
		DEBUG("Time: %ld", (long int) expire_time);
		if(r->request_time > expire_time) {
			DEBUG("Expire date is before request time, won't cache response");
			return 0;
		} else 
			*cachetime_interval = apr_time_sec((apr_time_from_sec(expire_time) - r->request_time));

	}

	return expire_time;
}

static wodan_default_cachetime_t* default_cachetime_longest_match(wodan_config_t *config,
	char *uri)
{
	wodan_default_cachetime_t *longest, *list;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan_default_cachetime_t*) config->default_cachetimes->elts;
	for(i=0; i < config->default_cachetimes->nelts; i++) {
		int l = (int) strlen(list[i].path);

		if(l > length && strncmp(list[i].path, uri, l) == 0) {
			longest = &list[i];
			length = l;
		}
	}
	return longest;
}

static wodan_default_cachetime_header_t* default_cachetime_header_match(wodan_config_t *config, apr_table_t *headers)
{
	wodan_default_cachetime_header_t *list;
	const char *header;
	char *header_value;
	int i;
	
	list = (wodan_default_cachetime_header_t*) config->default_cachetimes_header->elts;
	for (i = 0; i < config->default_cachetimes_header->nelts; i++) {
		header = list[i].header;
		header_value = (char*) apr_table_get(headers, header);
		
		if (header_value != NULL)
			if (ap_regexec(list[i].header_value_pattern, header_value, 0, NULL, 0) == 0)
				return &list[i];
	}
	return NULL;
}

static wodan_default_cachetime_regex_t* default_cachetime_regex_match(wodan_config_t *config, char *uri)
{
	wodan_default_cachetime_regex_t *list;
	int i;
	
	list = (wodan_default_cachetime_regex_t*) config->default_cachetimes_regex->elts;
	for (i = 0; i < config->default_cachetimes_regex->nelts; i++) {
		if (ap_regexec(list[i].uri_pattern, uri, 0, NULL, 0) == 0)
			return &list[i];
	}
	return NULL;
}
	
static int find_cache_time(T C)
{
	int cachetime;
	request_rec *r = C->r;

	wodan_default_cachetime_header_t *default_cachetime_header_config;
	wodan_default_cachetime_regex_t *default_cachetime_regex_config;
	wodan_default_cachetime_t *default_cachetime_config;
	
	default_cachetime_header_config = default_cachetime_header_match(C->config, C->R->headers);
	if (default_cachetime_header_config != NULL) {
		cachetime = default_cachetime_header_config->cachetime;
		DEBUG("Got cachetime from header match! cachetime = %d", cachetime);
		return cachetime;
	}

	default_cachetime_regex_config = default_cachetime_regex_match(C->config, C->r->uri);
	if (default_cachetime_regex_config != NULL) {
		cachetime = default_cachetime_regex_config->cachetime;
		DEBUG("Got cachetime from regex match! cachetime = %d", cachetime);
		return cachetime;
	}
	
	default_cachetime_config = default_cachetime_longest_match(C->config, C->r->uri);
	if (default_cachetime_config != NULL) {
		cachetime = default_cachetime_config->cachetime;
		DEBUG("Got cachetime from normal match cachetime = %d", cachetime);
		return cachetime;
	}
	DEBUG("Using normal cachetime %d", DEFAULT_CACHETIME);
	return DEFAULT_CACHETIME;
}

static char *get_expire_time(T C)
{
	int cachetime;
	char *expire_time_rfc822_string = NULL;
	char *xwodan;
	apr_time_t expire_time = 0;
	request_rec *r = C->r;
	
	if (strlen(C->expire_time))
		return C->expire_time;

	cachetime = find_cache_time(C);

	/* check X-Wodan header */
	if ((xwodan = (char *) apr_table_get(C->R->headers, "X-Wodan")) != NULL) {
		DEBUG("Found an X-Wodan header \"%s\"", xwodan);
		if (strncasecmp(xwodan, "no-cache", 8) == 0) {
			DEBUG("Header is 'no-cache'. Not caching..." );
			return NULL;
		} else if (strncasecmp(xwodan, "expire", 6) == 0) {
			expire_time = parse_xwodan_expire(C->r, xwodan, cachetime, &(C->interval));
			if (expire_time == 0)
				return NULL;
			expire_time_rfc822_string = apr_pcalloc(C->r->pool, APR_RFC822_DATE_LEN);
			apr_rfc822_date(expire_time_rfc822_string, expire_time);
		} else {
			if (cachetime == -1) {
				DEBUG("WodanDefaultCacheTime in httpd.conf is 'no-cache'. Not caching..." );
				return NULL;
			}
		}

	/* Expires header */
	} else if ((expire_time_rfc822_string = (char *) apr_table_get(C->R->headers, "Expires")) != NULL) {
		if (! (expire_time = apr_date_parse_http(expire_time_rfc822_string))) {
			DEBUG("Expires header invalid [%s]", expire_time_rfc822_string);
			expire_time_rfc822_string = NULL;
		} else if(C->r->request_time > expire_time) {
			DEBUG("Expires header in the past [%s]", expire_time_rfc822_string);
			expire_time_rfc822_string = NULL;
		} else {
			C->interval = apr_time_sec((expire_time - C->r->request_time));
			DEBUG("Expires header [%s] interval [%d]", expire_time_rfc822_string, C->interval);
		}
	}

	if ((expire_time_rfc822_string == NULL) || (C->interval == 0)) {
		expire_time = C->r->request_time + apr_time_from_sec(cachetime);
		C->interval = cachetime;
		expire_time_rfc822_string = apr_pcalloc(C->r->pool, APR_RFC822_DATE_LEN);
		apr_rfc822_date(expire_time_rfc822_string, expire_time);
		DEBUG("Using default cache time [%d] expires [%s]", cachetime, expire_time_rfc822_string);
	}

	apr_cpystrn(C->expire_time, expire_time_rfc822_string, sizeof(C->expire_time));
	
	return expire_time_rfc822_string;
}

static void create_cache_dir(T C, char *cachefilename)
{
	int i, result;
	char *subdir;
	struct stat dir_status;
	wodan_config_t *config = C->config;

	for (i = 0; i < config->cachedir_levels; i++) {
		subdir = get_cache_file_subdir(C, cachefilename, i);
		
		result = stat( subdir, &dir_status );
		if ((result != 0) || (! S_ISDIR(dir_status.st_mode)))
			mkdir(subdir, 0770);
	}

}

/**
 * @param cachefile the cache file
 * @param r request record
 * @param R H record
 * @param expire_time_string time at which cache expires.
 * @param expire_interval time interval between request and expire
 */
static int write_preamble(T C, apr_file_t *cachefile, char *expire_time_string)
{
	request_rec *r = C->r;
	Response_T *H = C->R;
	int expire_interval = C->interval;
	apr_file_printf(cachefile, "%s%s%s", r->hostname, r->unparsed_uri, CRLF);
	apr_file_printf(cachefile, "%d%s", expire_interval, CRLF);
	apr_file_printf(cachefile, "%s%s", expire_time_string, CRLF);
	apr_file_printf(cachefile, "%d%s", H->response, CRLF);
	/* TODO add error checking */
	{
		int i;
		const apr_array_header_t *headers_array = apr_table_elts(H->headers);
		apr_table_entry_t *headers_elts = (apr_table_entry_t *) headers_array->elts;
		
		for(i = 0; i < headers_array->nelts; i++) {
			apr_file_printf(cachefile, "%s: %s%s", headers_elts[i].key, headers_elts[i].val, CRLF);
		}
	}
	apr_file_printf(cachefile, "%s", CRLF);
	return 0;
}

apr_file_t *cache_get_cachefile(T C)
{
	apr_file_t *cache_file = NULL;
	char *expire = NULL;
	char *tempfile_template;
	char *temp_dir;	
	request_rec *r = C->r;

	if(!is_cachedir_set(C)) {
		ERROR("cachedir not set.");
		return NULL;
	}

	if (C->r->header_only) {
		DEBUG("Response isn't cacheable: HEAD");
		return NULL;
	}
	if (C->r->method_number != M_GET) {
		DEBUG("Response isn't cacheable: !GET");
		return NULL;
	}
	
	if (!is_response_cacheable(C->R->response, C->config->cache_404s)) {
		DEBUG("Response isn't cacheable: %d", C->R->response);
		return NULL;
	}
	if ((char *) ap_strcasestr(C->r->unparsed_uri, "cache=no") != NULL)
		return NULL;

	if ((expire = get_expire_time(C)) == NULL)
		return NULL;

	if (apr_temp_dir_get((const char **) &temp_dir, C->r->pool) != APR_SUCCESS) {
		ERROR("unable to find temp dir");
		return NULL;
	}

	tempfile_template = apr_psprintf(C->r->pool, "%s/wodan_temp_XXXXXX", temp_dir);
	if (apr_file_mktemp(&cache_file, tempfile_template, 0, C->r->pool) != APR_SUCCESS)
		return NULL;
	
	/* write url, expire, cache constraint and headers */
	if (write_preamble(C, cache_file, expire) == -1) {
		ERROR("error writing preamble to tempcachefile");
		apr_file_close(cache_file);
		return NULL;
	}
		
	return cache_file;
}

void cache_close_cachefile(T C, apr_file_t *temp_cachefile)
{
	const char * src;
	char *dst;

	// copy the temporary file into the real cache file 
	if (! temp_cachefile) return;

	if (! cache_filename(C, &dst)) return;

	create_cache_dir(C, dst);

	apr_file_name_get(&src, temp_cachefile);
	apr_file_copy(src, dst, APR_UREAD|APR_UWRITE|APR_GREAD, C->r->pool);
	apr_file_close(temp_cachefile);
}		

int cache_update_expiry_time(T C)
{

	request_rec *r = C->r;
	char *cachefilename;
	int expire_interval;
	long int expire_time;
	char *expire_time_string = NULL;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	apr_size_t bytes_written;

	if (! cache_filename(C, &cachefilename))
		return -1;

	if (apr_file_open(&cachefile, cachefilename, APR_READ|APR_WRITE, APR_OS_DEFAULT, C->r->pool) != APR_SUCCESS) 
		return -1;   

	/* skip URL field */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);

	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* calculate new expire_time */
	expire_interval = (int) strtol(buffer, NULL, 10);
	expire_time = apr_time_sec(C->r->request_time) + expire_interval;
	expire_time_string = apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
	apr_rfc822_date(expire_time_string, apr_time_from_sec(expire_time));
	/* write new expire time field in cachefile */
	DEBUG("%s", expire_time_string);
	apr_file_write_full(cachefile, expire_time_string, strlen(expire_time_string),
			&bytes_written);
	if (bytes_written != strlen(expire_time_string)) {
		ERROR("error writing to cachefile");
		apr_file_close(cachefile);
		return -1;
	}
	apr_file_flush(cachefile);
	apr_file_close(cachefile);
	return 0;
}

int receive_status_line(T C, apr_socket_t *socket)
{
	const char *s;

	if (! (s = connection_read_string(socket, C->r)))
		return -1;

	ap_getword_white(C->r->pool, &s);
	C->R->response = atoi(ap_getword_white(C->r->pool, &s));

	return C->R->response;
}

static const char* wodan_date_canon(apr_pool_t *p, const char *input_date_string)
{
	apr_time_t the_time;
	char *rfc822_date_string;

	the_time = apr_date_parse_rfc(input_date_string);
	if (the_time == APR_DATE_BAD)
		return input_date_string;

	rfc822_date_string = apr_pcalloc(p, APR_RFC822_DATE_LEN);
	apr_rfc822_date(rfc822_date_string, the_time);

	return rfc822_date_string;
}

/** adjust dates to one form */
static void adjust_dates(T C)
{
	const char* datestr = NULL;
	char *interval = apr_pcalloc(C->r->pool, APR_RFC822_DATE_LEN);

	if ((datestr = apr_table_get(C->R->headers, "Date")))
		apr_table_set(C->R->headers, "Date", wodan_date_canon(C->r->pool, datestr));

	if ((datestr = get_expire_time(C)))
		apr_table_set(C->R->headers, "Expires", wodan_date_canon(C->r->pool, datestr));

	apr_rfc822_date(interval, C->mtime);
	apr_table_set(C->R->headers, "Last-Modified", interval);
}


int receive_headers(T C, apr_socket_t *socket)
{
	const char *read_header;
	char *header; // only used as a workaround for when read_header is
	// not big enough to store the incoming header, for
	// example with large Set-Cookie headers
	char *key, *val;
	int val_pos, len;
	
	request_rec *r = C->r;

	header = 0;
	while((read_header = connection_read_string(socket, C->r))) {
		/* if read_header is NULL, this signals an error. Escape from here right
		 * away in that case */
		if (read_header == NULL)
			return HTTP_BAD_GATEWAY;

		if (strcasecmp(read_header, CRLF) == 0)
			break;

		len = 0;
		if(strlen(read_header) == BUFFERSIZE - 1) {
			if(header) 
				len = strlen(header);
			header = (char *) realloc(header, (len + BUFFERSIZE));
			header = strncat(header, read_header, BUFFERSIZE);
			continue;
		}

		if(header) { // we append the final bytes of header here
			len = strlen(header);
			header = (char *) realloc(header, (len + BUFFERSIZE));
			header = strcat(header, read_header);
		}

		key = ap_getword(C->r->pool, header ? (const char **)&header: &read_header, ':');
		val = apr_pstrdup(C->r->pool, header ? header : read_header);
		val = util_skipspaces(val);

		// strip whitespace from start and end.
		val_pos = 0;
		while(val[val_pos]) {
			if (val[val_pos] == CR || val[val_pos] == LF) {
				val[val_pos] = '\0';
				break;
			}
			val_pos++;
		}
		apr_table_add(C->R->headers, key, val);
		free(header);
		DEBUG("Added response header: [%s: %s]", key, val);
	}
	/* adjust headers */
	ap_reverseproxy_clear_connection(C->r->pool, C->R->headers);
	adjust_dates(C);
	C->R->headers = apr_table_overlay(C->r->pool, C->r->err_headers_out, C->R->headers);

	return OK;
}

int receive_body(T C, apr_socket_t *socket, apr_file_t *cache_file)
{
	char *buffer;
	int nr_bytes_read;
	int writtenbytes;
	int body_bytes_written;
	int backend_read_error, client_write_error, cache_write_error;

	request_rec *r = C->r;

	buffer = apr_pcalloc(r->pool, BUFFERSIZE);

	body_bytes_written = 0;
	backend_read_error = 0;
	client_write_error = 0;
	cache_write_error = 0;

	while(1)
	{
		nr_bytes_read = connection_read_bytes(socket, C->r, buffer, BUFFERSIZE);

		DEBUG("read %d bytes from backend", nr_bytes_read);
		
		if (nr_bytes_read == -1) backend_read_error = 1;

		/* write to cache and check for errors */
		if (cache_file) {
			apr_size_t cache_bytes_written;
			apr_file_write_full(cache_file, buffer, nr_bytes_read, &cache_bytes_written);

			if ((int) cache_bytes_written < nr_bytes_read) {
				cache_write_error = 1;
				break;
			}
		}
					
		if (!C->r->header_only) {
			writtenbytes = ap_rwrite(buffer, nr_bytes_read, C->r);
			body_bytes_written += writtenbytes;
			/* escape from loop if there's an error */
			if (writtenbytes < 0 || 
			    writtenbytes != nr_bytes_read) {
			    client_write_error = 1;
				break;
			}
		}
			
		/* last escape hatch */
		if (nr_bytes_read == 0)
			break;
	}
	
	/* handle the possible errors */
	if (client_write_error) {
		/* add a more explicit error message to the error_log
		 * including User-Agent and Content-Length */
		const char *user_agent;
		const char *content_length_str;
		int content_length;
		
		user_agent = apr_table_get(C->r->headers_in, "User-Agent");
		if (user_agent == NULL)
			user_agent = "unknown";
		content_length_str = apr_table_get(C->R->headers, "Content-Length");
		content_length = (content_length_str) ?  atoi(content_length_str): 0;
					
		ERROR("Error writing to client. " 
				"Bytes written/total bytes = %d/%d, " 
				"User-Agent: %s", body_bytes_written, content_length, user_agent);
		return HTTP_BAD_GATEWAY;
	}

	if (cache_write_error) {
		ERROR("Error writing to cache file");
		ap_rflush(C->r);
		return HTTP_BAD_GATEWAY;
	}

	if (backend_read_error) {
		ERROR("Error reading from backend");
		return HTTP_BAD_GATEWAY;
	}
	
	/* everything went well. Close cache file and make sure
	 * all content goes to the client */
	cache_close_cachefile(C, cache_file);
	ap_rflush(C->r);

	return OK;
}
/**
 * send request line and Host header
 * @param connection connection struct
 * @param r request record
 * @param dest_path destination path
 * @retval -1 on error.
 */
static int send_request(T, apr_socket_t *, const char *, const char *);

/**
 * send headers to client. Also sends the empty newline after headers.
 * @param connection connection struct
 * @param r request record
 * @param headers the headers
 * @retval OK on succes
 * @retval -1 on failure.
 */
static int send_headers(apr_socket_t *socket, request_rec *r, const apr_table_t *headers);


/**
 * Remove all connection based header from the table
 * Copied from mod_proxy
 */

void ap_reverseproxy_clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    const char *name;
    char *next = apr_pstrdup(p, apr_table_get(headers, "Connection"));

    /* Some proxies (Squid, ICS) use the non-standard "Proxy-Connection" 
       header. */
    apr_table_unset(headers, "Proxy-Connection");

    if (next != NULL) {
       while (*next) {
	       name = next;
	       while (*next && !apr_isspace(*next) && (*next != ','))
                    ++next;
               while (*next && (apr_isspace(*next) || (*next == ','))) {
                    *next = '\0';
                    ++next;
               }
               apr_table_unset(headers, name);
        }
        apr_table_unset(headers, "Connection");
    }

    apr_table_unset(headers,"Keep-Alive");
    apr_table_unset(headers,"Proxy-Authenticate");
    apr_table_unset(headers,"TE");
    apr_table_unset(headers,"Trailer");
    apr_table_unset(headers,"Transfer-Encoding");
    apr_table_unset(headers,"Upgrade");
}    

/**
 * get all parts of the backend url
 * @param[in] pool pointer to memory pool
 * @param[in] proxyurl the complete destination url
 * @param[in] uri the requested uri
 * @param[out] desthost destination host
 * @param[out] destport destination port
 * @param[out] destpath destination path
 * @param[out] dest_host_and_port host:port (e.g. www.ic-s.nl:80)
 * @param[out] do_ssl will be set to one if we need to do ssl to
 *             the backend.
 */

static apr_status_t get_destination_parts(apr_pool_t *p,
			  const char *proxy_url, const char *uri,
			  char **dest_host, int *dest_port, char **dest_path,
			  char **dest_host_and_port, int *do_ssl) 
{
	apr_uri_t uptr;
	char *tmp_path;
	int uri_parse_retval;
	
	if ((uri_parse_retval = apr_uri_parse(p, proxy_url, &uptr)) != APR_SUCCESS)
		return uri_parse_retval;
	
	*do_ssl = (strncmp(uptr.scheme, "https", 5) == 0) ? 1 : 0;

	*dest_host = apr_pstrdup(p, uptr.hostname);

	if (uptr.port_str == NULL)
		*dest_port = DEFAULT_HTTP_PORT;
	else
		*dest_port = uptr.port;

	/* for some reason, uptr.path isn't always at least '/' (the
	 * O'Reilly book says it should), so we have to check for that */
	if (uptr.path == NULL) 
		tmp_path = apr_pstrdup(p, "");
	else {
		tmp_path = apr_pstrdup(p, uptr.path);
		size_t l = strlen(tmp_path)-1;
		/* tmp_path is "/" or longer, always ending in '/'. We need to
		 * strip this / */
		if (tmp_path[l] == '/') 
			tmp_path[l] = '\0';
	}

	*dest_path = apr_pstrcat(p, tmp_path, uri, NULL);

	*dest_host_and_port = apr_psprintf(p, "%s:%d", *dest_host, *dest_port);
	return APR_SUCCESS;
}

/**
 * send request body
 * @param connection connection struct
 * @param r request record
 */

static int send_request_body(apr_socket_t *socket, request_rec *r)
{
	int n;

	if ((n = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)))
		return n;
	
	if (ap_should_client_block(r)) {
		char buffer[BUFFERSIZE];

		while ((n = ap_get_client_block(r, buffer, BUFFERSIZE)) > 0) { 
			if (connection_write_bytes(socket, r, buffer, n) == -1) 
				return -1;
		}
	}
	return OK;
}

/**
 * add X-headers to table.
 * @param r request_rec
 * @param out_headers_to_backend table of headers to send to the backend.
 */

static void add_x_headers(const request_rec *r, apr_table_t *out_headers_to_backend)
{
	const char *temp;

	/* Add X-Forwarded-For so the backend can find out where the 
	 * request came from. If there's already a X-Forwarded-For
	 * header, the remote_ip is added to that header */
	apr_table_mergen(out_headers_to_backend, "X-Forwarded-For", r->connection->remote_ip);

	/* With X-Forwarded-Host, the backend can determine the original
	 * Host: header send to Wodan */
	if ((temp = apr_table_get(r->headers_in, "Host"))) 
		apr_table_mergen(out_headers_to_backend, "X-Forwarded-Host", temp);

	/* Add this server (the server Wodan runs on) as the X-Forwarded-Server,
	   The backend can determine the frontend servername by this. */
	apr_table_mergen(out_headers_to_backend, "X-Forwarded-Server", r->server->server_hostname);

	/* Pass the protocol used for client<->wodan communication through
	 * to the backend. */
	apr_table_set(out_headers_to_backend, "X-Wodan-Protocol", r->protocol);
}


/**
 * does a request for a url to the backend.
 * @param connection connection struct
 * @param r request_rec
 * @param dest_host destination host
 * @param dest_path destination path
 * @param out_headers headers sent to backend
 */

static int send_complete_request(T C, apr_socket_t *socket,
		const char *dest_host_and_port, const char *dest_path, apr_table_t *out_headers)
{
	int result;

	if(send_request(C, socket, dest_host_and_port, dest_path) < 0)
		return -1;

	add_x_headers(C->r, out_headers);
	apr_table_set(out_headers, "Connection", "close");
	apr_table_unset(out_headers, "Via");
	if (send_headers(socket, C->r, out_headers) == -1)
		return -1;

	if((result = send_request_body(socket, C->r)))
		return result;
	
	return OK;
}

static int send_request(T C, apr_socket_t *socket, const char *dest, const char *path) 
{
	const char *request;
	
	request = apr_psprintf(C->r->pool, "%s %s HTTP/1.0%sHost: %s%s", C->r->method, path, CRLF, dest, CRLF);
	if (connection_write_string(socket, C->r, request) == -1)
		return -1;

	if (C->mtime != APR_DATE_BAD) {
		char if_modified[APR_RFC822_DATE_LEN];
		const char *if_modified_header;
		if (apr_rfc822_date(&(if_modified[0]), C->mtime) != APR_SUCCESS) 
			return -1;
			
		if_modified_header = apr_psprintf(C->r->pool, "If-Modified-Since: %s%s", if_modified, CRLF);
		
		if (connection_write_string(socket, C->r, if_modified_header) == -1)
			return -1;
	} 
	return OK;
}

static int send_headers(apr_socket_t *socket, request_rec *r, const apr_table_t *headers) 
{
	int i;
	const char *header_string;
	const apr_array_header_t *headers_array = apr_table_elts(headers);
	apr_table_entry_t *headers_elts = (apr_table_entry_t *) headers_array->elts;

	for (i = 0; i < headers_array->nelts; i++) {
		/* the following headers should not be sent to the
		   backend. */
		if(headers_elts[i].key == NULL || headers_elts[i].val == NULL || 
		   !strncasecmp(headers_elts[i].key, "Host", 4) || 
		   !strncasecmp(headers_elts[i].key, "Keep-Alive", 10) || 
		   !strncasecmp(headers_elts[i].key, "TE", 2) || 
		   !strncasecmp(headers_elts[i].key, "Trailer", 7) || 
		   !strncasecmp(headers_elts[i].key, "Transfer-Encoding", 17) || 
		   !strncasecmp(headers_elts[i].key, "Proxy-Authorization", 19) ||
		   !strncasecmp(headers_elts[i].key, "If-Modified-Since", 17) ||
		   !strncasecmp(headers_elts[i].key, "Cache-Control", 12) ||
		   !strncasecmp(headers_elts[i].key, "If-None-Match", 12))
		{
			continue;
		}
		header_string = apr_psprintf(r->pool, "%s: %s%s",
					    headers_elts[i].key,
					    headers_elts[i].val, 
					    CRLF);
		if (connection_write_string(socket, r, header_string) == -1)
			return -1;
	}
	/* add empty line, signals end of headers */
	header_string = apr_psprintf(r->pool, "%s", CRLF);
	if (connection_write_string(socket, r, header_string) == -1)
		return -1;

	return OK;
}
       
/** receive the whole response from the backend 
 * @param connection connection to backend
 * @param r request_rec
 * @param R will hold response
 * @return OK if finished
 */
static int receive_complete_response(T C, apr_socket_t *socket)
{
	int status = OK;
	int receive_headers_result;
	int receive_body_result;
	apr_file_t *cache_file = NULL;

	if ((status = receive_status_line(C, socket)) == -1) {
		C->R->response = HTTP_BAD_GATEWAY;
		return HTTP_BAD_GATEWAY;
	}
	
	if (ap_is_HTTP_SERVER_ERROR(status)) { /* = 50x */
		C->R->response = HTTP_BAD_GATEWAY;
		return status;
	}

	if (status == HTTP_NOT_MODIFIED) {
		C->R->response = status;
		return status;
	}
	
	if ((receive_headers_result = receive_headers(C, socket))) {
		C->R->response = HTTP_BAD_GATEWAY;
		return receive_headers_result;
	}
	
	switch(status) {
		case HTTP_OK:
		case HTTP_NOT_FOUND: 
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_MOVED_TEMPORARILY:
		case HTTP_SEE_OTHER:
			cache_file = cache_get_cachefile(C);
			break;
		default:
			cache_file = (apr_file_t *)NULL;
			break;
	}

	adjust_headers_for_sending(C);
	
	if ((receive_body_result = receive_body(C, socket, cache_file))) {
		C->R->response = HTTP_BAD_GATEWAY;
		return receive_body_result;
	}

	return status;
}

static apr_socket_t* connection_open (T C, char* host, int port, int do_ssl UNUSED)
{
	apr_status_t result;
	apr_socket_t *socket;
	apr_sockaddr_t *server_address;
	request_rec *r = C->r;
	
	if (apr_sockaddr_info_get(&server_address, host, APR_UNSPEC, port, 0, C->r->pool) != APR_SUCCESS) {
		ERROR("Hostname lookup failure for: %s", host);
		return NULL;
	}
	
	if (apr_socket_create(&socket, APR_INET, SOCK_STREAM, APR_PROTO_TCP, C->r->pool) != APR_SUCCESS) {
		ERROR("Error creating socket");
		return NULL;
	}

	if (C->config->backend_timeout > 0) {
		apr_socket_timeout_set(socket, C->config->backend_timeout);
		DEBUG("socket timeout set to %ld", C->config->backend_timeout);
	}
	if ((result = apr_socket_connect(socket, server_address)) != APR_SUCCESS) {
		char err_buf[255];
		memset(&err_buf,0,sizeof(err_buf));
		ERROR("Socket error at %s:%d - [%s]", host, port, apr_strerror(result, err_buf, sizeof(err_buf)));
		return NULL;
	}
	DEBUG("Succesfully connected to %s:%d", host, port);

	return socket;
}

static wodan_proxy_destination_t* destination_longest_match(T C)
{
	wodan_proxy_destination_t *longest, *list;
	wodan_config_t *config = C->config;
	char *uri = C->r->unparsed_uri;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan_proxy_destination_t *) config->proxy_passes->elts;
	for(i=0; i < config->proxy_passes->nelts; i++) {
		int l = (int) strlen(list[i].path);

		if(l > length && strncmp(list[i].path, uri, l) == 0) {
			longest = &list[i];
			length = l;
		}
	}
	return longest;	
}

int cache_update_fetch(T C)
{
	request_rec *r = C->r;

	int result = OK;
	char *desthost, *destpath;
	char *dest_host_and_port;
	int destport;
	int do_ssl;
	apr_table_t *out_headers;
	apr_socket_t *socket;

	wodan_proxy_destination_t *proxy;

	if (! (proxy = destination_longest_match(C)))
		return DECLINED;

	int l = (int) strlen(proxy->path);
	char *uri = &(C->r->unparsed_uri[l - 1]);

	if (get_destination_parts(C->r->pool, proxy->url, uri, &desthost, &destport,
				  &destpath, &dest_host_and_port,
				  &do_ssl)) {
		ERROR("failed to parse proxy_url %s and uri %s", proxy->url, uri);
		return DECLINED;
	}
		
	DEBUG("Destination: %s %d %s", desthost, destport, destpath);
	
	//Connect to proxyhost
	socket = connection_open(C, desthost, destport, do_ssl);
	if(socket == NULL) {
		C->R->response = HTTP_BAD_GATEWAY;
		return HTTP_BAD_GATEWAY;
	}

	//Copy headers and make adjustments
	out_headers = apr_table_copy(C->r->pool, C->r->headers_in);
	ap_reverseproxy_clear_connection(C->r->pool, out_headers);
	
	/* send request */
	if (send_complete_request(C, socket, dest_host_and_port, destpath, out_headers) == -1) {
		apr_socket_close(socket);
		C->R->response = HTTP_BAD_GATEWAY;
		return HTTP_BAD_GATEWAY;
	}	
	
	result = receive_complete_response(C, socket);

	apr_socket_close(socket);

	return result;
}
	
int cache_update (T C) 
{
	if ((cache_update_fetch(C) == DECLINED))
		return DECLINED;

	/* If 404 are to be cached, then already return
	 * default 404 page here in case of a 404. */
	if ((C->config->cache_404s) && (C->R->response == HTTP_NOT_FOUND))
		return C->r->status = C->R->response;

	/* if nothing can be received from backend, and there's
	   nothing in cache, return the response code so
	   ErrorDocument can handle it ... */
	if (C->status != WODAN_CACHE_EXPIRED && (ap_is_HTTP_SERVER_ERROR(C->R->response) || (C->R->response == HTTP_NOT_FOUND))) {
		if (C->config->run_on_cache)
			C->R->response = HTTP_NOT_FOUND;
		return C->r->status = C->R->response;
	}

	if (C->status == WODAN_CACHE_EXPIRED && (ap_is_HTTP_SERVER_ERROR(C->R->response) || (C->R->response == HTTP_NOT_MODIFIED))) {
		cache_update_expiry_time(C);
		cache_read(C);
		return C->r->status = C->R->response = HTTP_OK;
	}

	return C->r->status = C->R->response;
}

//EOF
