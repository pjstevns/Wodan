/** $Id: cache.c 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */

#include <sys/stat.h>
#include <string.h>
#include <assert.h>

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


typedef struct {
	char *url;
	int ttl;
	apr_time_t expire;
	int status;
} WodanCacheHeader_T;

/**
 * \brief check if the CacheDir directive is set
 * \param config the server configuration
 * \return 
 *     - 0 if not set
 *     - 1 if set
 */
static int is_cachedir_set(wodan_config_t* config)
{
	if (config->is_cachedir_set)
		return 1;
	return 0;
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
	if ( cache404s && (httpcode == 404))
		return 1;

	if ( httpcode == 304 )
		return 0;

	if (ap_is_HTTP_SUCCESS(httpcode))
		return 1;
	if (ap_is_HTTP_REDIRECT(httpcode))
		return 1;

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
static char *get_cache_file_subdir(wodan_config_t *config, request_rec *r, 
				   char *cachefilename, int nr)
{
	int count;
	char *ptr;
	char *buffer;

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

static int get_cache_filename(wodan_config_t *config, request_rec *r, char **filename )
{
	unsigned char digest[APR_SHA1_DIGESTSIZE];
	char dir[MAX_CACHEFILE_PATH_LENGTH + 1];
	char *checksum;
	char *ptr;
	int i;
	struct apr_sha1_ctx_t sha;

	apr_array_header_t *headers;

	apr_sha1_init(&sha);
	apr_sha1_update(&sha, r->unparsed_uri, strlen(r->unparsed_uri));

	/* handle WodanHashHeader directives */
	headers = config->hash_headers;
        if (headers) {
                int i = 0;
                for(i = 0; i < headers->nelts; i++) {
			const char *key = ((const char **)headers->elts)[i];
			const char *value = apr_table_get(r->headers_in, key);

			if (value) {
				DEBUG("Found header for hash [%s: %s]", key, value);
				apr_sha1_update(&sha, value, strlen(value));
			}
                }
        }

	/* handle WodanHashHeaderMatch directives */
	headers = config->hash_headers_match;
        if (headers) {
                int i = 0;
		wodan_hash_header_match_t *match = (wodan_hash_header_match_t *)headers->elts;
                for(i = 0; i < headers->nelts; i++) {
			const char *key = match[i].header;
			ap_regex_t *exp = match[i].regex;
			const char *rep = match[i].pattern;

			DEBUG("Lookup header [%s]", match[i].header);

			const char *val, *value = apr_table_get(r->headers_in, key);

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

	checksum = sha1_to_hex(r, digest);

	/* If cachedir + subdirs + checksum don't fit in buffer, 
	 * we have a problem */
	if (strlen(config->cachedir) > 
	     (MAX_CACHEFILE_PATH_LENGTH - 32 - (2 * MAX_CACHEDIR_LEVELS))) {
		ERROR("Cachefile pathname doesn't fit into buffer.");
		*filename = NULL;
		return 0;
	}

	apr_cpystrn(dir, config->cachedir, MAX_CACHEFILE_PATH_LENGTH + 1);
	ptr = &dir[0] + (int) strlen(dir);
	
	if (*ptr == '/')
		ptr--;

	for (i = 0; i < config->cachedir_levels; i++) {
		ptr[0] = '/';
		ptr[1] = checksum[i];
		ptr += 2;
	}
	*ptr = '\0';

	*filename = ap_make_full_path(r->pool, dir, checksum);

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
static void wodan_table_add_when_empty(apr_table_t *base, apr_table_t *overlay)
{
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

static void apply_proxy_pass_reverse(wodan_config_t *config, apr_table_t* headers,
	request_rec *r)
{
	const char* url;
	wodan_proxy_alias_t *alias;

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



void adjust_headers_for_sending(cache_state_t *cachestate)
{

	wodan_config_t *config = cachestate->config;
	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;

	/* do more adjustments to the headers. This used to be in 
	   mod_reverseproxy.c */
	apr_table_unset(httpresponse->headers, "X-Wodan");
	wodan_table_add_when_empty(httpresponse->headers, r->headers_out);
	apply_proxy_pass_reverse(config, httpresponse->headers, r);
	
	r->headers_out = httpresponse->headers;
	r->content_type = apr_table_get(httpresponse->headers, "Content-Type");
	r->status = httpresponse->response;
}


WodanCacheStatus_t cache_status(cache_state_t *cachestate)
{

	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int status;
	int interval_time = 0;
	long int ttl;
	wodan_config_t *config = cachestate->config;
	request_rec *r = cachestate->r;
	apr_time_t cache_file_time = cachestate->cache_file_time;
	char ** cachefilename = &(cachestate->cachefilename);

	if(r->method_number != M_GET && !r->header_only)
		return WODAN_CACHE_NOT_CACHEABLE;

	// if the CacheDir directive is not set, we cannot read from cache
	if (!is_cachedir_set(config))
		return WODAN_CACHE_NOT_PRESENT;

	if (! get_cache_filename(config, r, cachefilename))
		return WODAN_CACHE_NOT_CACHEABLE;

	if (apr_file_open(&cachefile, *cachefilename, APR_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		return WODAN_CACHE_NOT_PRESENT;
	}

	/* Read url field, but we don't do anything with it */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);

	/* read expire interval field */
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		if (! (interval_time = atoi(buffer))) {
		
			DEBUG("unlink cachefile with interval_time 0");
			const char *fname;
			apr_file_name_get(&fname, cachefile);
			apr_file_remove(fname, r->pool);
			apr_file_close(cachefile);
			return WODAN_CACHE_NOT_PRESENT;
		}
	}

	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		float rand;
		apr_time_t cachefile_expire_time;

		/* Parses a date in RFC 822  */
		if ((cachefile_expire_time = apr_date_parse_http(buffer)) == APR_DATE_BAD) {
			DEBUG("Cachefile date not parsable. Returning \"Expired status\"");
			return WODAN_CACHE_PRESENT_EXPIRED;
		}

		/* time - interval_time = time that file was created */
		cache_file_time = cachefile_expire_time - apr_time_from_sec(interval_time);
		ttl =  ((long int) cachefile_expire_time - (long int) r->request_time)/1000000;

		DEBUG("interval [%d], ttl [%ld]", interval_time, ttl);

		if(ttl <= 0) {
			apr_file_close(cachefile);
			return WODAN_CACHE_PRESENT_EXPIRED;
		}

		// get a random number 
		rand = get_random_number(100000);

		if (ttl < (interval_time/10)) {
			if (rand <= 0.001) {
				apr_file_close(cachefile);
				return WODAN_CACHE_PRESENT_EXPIRED;
			}
		} else if (ttl < (interval_time/5)) {
			if (rand <= 0.0001) {
				apr_file_close(cachefile);
				return WODAN_CACHE_PRESENT_EXPIRED;
			}
		} else if (ttl < (interval_time/4)) {
			if (rand <= 0.00005) {
				apr_file_close(cachefile);
				return WODAN_CACHE_PRESENT_EXPIRED;
			}
		}

		if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
			status = atoi(buffer);
			if (status == HTTP_NOT_FOUND) {
				if (config->cache_404s) {
					DEBUG("cache status [404] while Cache404s is On");
					apr_file_close(cachefile);
					return WODAN_CACHE_404;
				}
				DEBUG("unlink cached [404] while Cache404s is Off");
				const char *fname;
				apr_file_name_get(&fname, cachefile);
				apr_file_remove(fname, r->pool);
				apr_file_close(cachefile);
				return WODAN_CACHE_NOT_PRESENT;
			}
		}
		while (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
			if (strncasecmp(buffer, "Last-Modified", 13) == 0) {
				if (strlen(buffer) > 40) {
					apr_time_t last_modified;
					if ((last_modified = apr_date_parse_http(buffer+14))) {
						cache_file_time = last_modified;
					}
				}
				break;
			}

			if ((strncmp(buffer, "\r\n", 2) == 0) || (strncmp(buffer,"\n",1) == 0))
				break;
		}


		apr_file_close(cachefile);
		return WODAN_CACHE_PRESENT;
	}
	apr_file_close(cachefile);
	return WODAN_CACHE_NOT_PRESENT;
}

int cache_read(cache_state_t *cachestate)
{
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int write_error;
	int content_length = 0;
	int body_bytes_written = 0;
	
	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;
	char **cachefilename = &(cachestate->cachefilename);

	const char *ifmodsince;
	if ((ifmodsince = apr_table_get(r->headers_in, "If-Modified-Since"))) {
		apr_time_t if_modified_since;
		if ((if_modified_since = apr_date_parse_http(ifmodsince))) {
			if (cachestate->cache_file_time <= if_modified_since) {
				httpresponse->response = HTTP_NOT_MODIFIED;
				return 0;
			}
		}
	}

	apr_file_open(&cachefile, *cachefilename, APR_READ, APR_OS_DEFAULT, r->pool);
	/* Read url field, but we don't do anything with it */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* same for expire interval field */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* same for expire field */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);

	if(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		httpresponse->response = atoi(buffer);
	} else {
		//Remove file and return 0
		apr_file_close(cachefile);
		apr_file_remove(*cachefilename, r->pool);
		return 0;
	}

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
		apr_table_add(httpresponse->headers, key, bufferpointer);
		if (strncasecmp(key, "Content-Length", 14) == 0)
			content_length = atoi(bufferpointer);
	}

	adjust_headers_for_sending(cachestate);

	if(r->header_only)
		return 1;

	write_error = 0;
	/* TODO add checking of errors in reading from file */
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
	DEBUG("%s OK content-length: %d, body_bytes: %d", *cachefilename, content_length, body_bytes_written);

	return 1;
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
	
static int find_cache_time(wodan_config_t *config,
			 request_rec *r,
			 struct httpresponse *httpresponse)
{
	int cachetime;
	wodan_default_cachetime_header_t *default_cachetime_header_config;
	wodan_default_cachetime_regex_t *default_cachetime_regex_config;
	wodan_default_cachetime_t *default_cachetime_config;
	
	if (httpresponse != NULL) {
		default_cachetime_header_config = default_cachetime_header_match(config, httpresponse->headers);
		if (default_cachetime_header_config != NULL) {
			cachetime = default_cachetime_header_config->cachetime;
			DEBUG("Got cachetime from header match! cachetime = %d", cachetime);
		  return cachetime;
		}
	}

	default_cachetime_regex_config = default_cachetime_regex_match(config, r->uri);
	if (default_cachetime_regex_config != NULL) {
		cachetime = default_cachetime_regex_config->cachetime;
		DEBUG("Got cachetime from regex match! cachetime = %d", cachetime);
		return cachetime;
	}
	
	default_cachetime_config = default_cachetime_longest_match(config, r->uri);
	if (default_cachetime_config != NULL) {
		cachetime = default_cachetime_config->cachetime;
		DEBUG("Got cachetime from normal match cachetime = %d", cachetime);
		return cachetime;
	}
	DEBUG("Using normal cachetime %d", DEFAULT_CACHETIME);
	return DEFAULT_CACHETIME;
}

static char *get_expire_time(wodan_config_t *config,
		      request_rec *r, struct httpresponse *httpresponse,
		      int *cachetime_interval)
{
	int cachetime;
	char *expire_time_rfc822_string = NULL;
	char *xwodan;
	apr_time_t expire_time = 0;
	
	*cachetime_interval = 0;
	cachetime = find_cache_time(config, r, httpresponse);
	/* check X-Wodan header */
	if (httpresponse && (xwodan = (char *) apr_table_get(httpresponse->headers, "X-Wodan")) != NULL) {
		DEBUG("Found an X-Wodan header \"%s\"", xwodan);
		if (strncasecmp(xwodan, "no-cache", 8) == 0) {
			DEBUG("Header is 'no-cache'. Not caching..." );
			return NULL;
		} else if (strncasecmp(xwodan, "expire", 6) == 0) {
			expire_time = parse_xwodan_expire(r, xwodan, 
							  cachetime,
							  cachetime_interval);
			if (expire_time == 0)
				return NULL;
			expire_time_rfc822_string = apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
			apr_rfc822_date(expire_time_rfc822_string, expire_time);
		} else {
			if (cachetime == -1) {
				DEBUG("WodanDefaultCacheTime in httpd.conf is 'no-cache'. Not caching..." );
				return NULL;
			}
		}
		/* check X-Wodan header */
	} else if (httpresponse && (expire_time_rfc822_string = (char *) apr_table_get(httpresponse->headers, "Expires")) != NULL) {
		if (! (expire_time = apr_date_parse_http(expire_time_rfc822_string))) {
			DEBUG("Expires header invalid [%s]", expire_time_rfc822_string);
			expire_time_rfc822_string = NULL;
		} else if(r->request_time > expire_time) {
			DEBUG("Expires header in the past [%s]", expire_time_rfc822_string);
			expire_time_rfc822_string = NULL;
		} else {
			*cachetime_interval = apr_time_sec((expire_time - r->request_time));
			DEBUG("Expires header [%s] interval [%d]", expire_time_rfc822_string, *cachetime_interval);
		}
	
	}

	if ((expire_time_rfc822_string == NULL) || (*cachetime_interval == 0)) {
		expire_time = r->request_time + apr_time_from_sec(cachetime);
		*cachetime_interval = cachetime;
		DEBUG("Using default cache time [%d]", cachetime);
		expire_time_rfc822_string = apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
		apr_rfc822_date(expire_time_rfc822_string, expire_time);
	}
	return expire_time_rfc822_string;
}

static void create_cache_dir(wodan_config_t *config, request_rec *r, char *cachefilename)
{
	int i, result;
	char *subdir;
	struct stat dir_status;

	for (i = 0; i < config->cachedir_levels; i++) {
		subdir = get_cache_file_subdir(config, r, cachefilename, i);
		
		result = stat( subdir, &dir_status );
		if ((result != 0) || (! S_ISDIR(dir_status.st_mode)))
			mkdir(subdir, 0770);
	}

}

/**
 * @param cachefile the cache file
 * @param r request record
 * @param httpresponse httpresponse record
 * @param expire_time_string time at which cache expires.
 * @param expire_interval time interval between request and expire
 */
static int write_preamble(apr_file_t *cachefile, request_rec *r,
			  httpresponse_t *httpresponse, 
			  char *expire_time_string,
			  int expire_interval)
{
	apr_file_printf(cachefile, "%s%s%s", r->hostname, r->unparsed_uri, CRLF);
	apr_file_printf(cachefile, "%d%s", expire_interval, CRLF);
	apr_file_printf(cachefile, "%s%s", expire_time_string, CRLF);
	apr_file_printf(cachefile, "%d%s", httpresponse->response, CRLF);
	/* TODO add error checking */
	{
		int i;
		const apr_array_header_t *headers_array = apr_table_elts(httpresponse->headers);
		apr_table_entry_t *headers_elts = (apr_table_entry_t *) headers_array->elts;
		
		for(i = 0; i < headers_array->nelts; i++) {
			apr_file_printf(cachefile, "%s: %s%s", headers_elts[i].key, headers_elts[i].val, CRLF);
		}
	}
	apr_file_printf(cachefile, "%s", CRLF);
	return 0;
}

apr_file_t *cache_get_cachefile(cache_state_t *cachestate)
{
	apr_file_t *cache_file = NULL;
	char *expire = NULL;
	int expire_interval = 0;
	char *tempfile_template;
	char *temp_dir;	
	
	wodan_config_t *config = cachestate->config;
	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;

	if(!is_cachedir_set(config)) {
		ERROR("cachedir not set.");
		return NULL;
	}

	if (r->header_only) {
		DEBUG("Response isn't cacheable: HEAD");
		return NULL;
	}
	if (r->method_number != M_GET) {
		DEBUG("Response isn't cacheable: !GET");
		return NULL;
	}
	
	if (!is_response_cacheable(httpresponse->response, config->cache_404s)) {
		DEBUG("Response isn't cacheable: %d", httpresponse->response);
		return NULL;
	}
	if ((char *) ap_strcasestr(r->unparsed_uri, "cache=no") != NULL)
		return NULL;

	if ((expire = get_expire_time(config, r, httpresponse, &expire_interval)) == NULL)
		return NULL;
	
	if (apr_temp_dir_get((const char **) &temp_dir, r->pool) != APR_SUCCESS) {
		ERROR("unable to find temp dir");
		return NULL;
	}

	tempfile_template = apr_psprintf(r->pool, "%s/wodan_temp_XXXXXX", temp_dir);
	if (apr_file_mktemp(&cache_file, tempfile_template, 0, r->pool) != APR_SUCCESS)
		return NULL;
	
	/* write url, expire, cache constraint and headers */
	if (write_preamble(cache_file, r, httpresponse, expire, expire_interval) == -1) {
		ERROR("error writing preamble to tempcachefile");
		apr_file_close(cache_file);
		return NULL;
	}
		
	return cache_file;
}

void cache_close_cachefile(wodan_config_t *config, request_rec *r, apr_file_t *temp_cachefile)
{
	const char * src;
	char *dst;

	// copy the temporary file into the real cache file 
	if (!temp_cachefile) {
		DEBUG("no temp cachefile");
		return;
	}

	if (! get_cache_filename(config, r, &dst))
		return;

	create_cache_dir(config, r, dst);

	apr_file_name_get(&src, temp_cachefile);
	apr_file_copy(src, dst, APR_UREAD|APR_UWRITE|APR_GREAD, r->pool);
	apr_file_close(temp_cachefile);
}		

int cache_update_expiry_time(cache_state_t *cachestate)
{

	wodan_config_t *config = cachestate->config;
	request_rec *r = cachestate->r;
	char *cachefilename;
	int expire_interval;
	long int expire_time;
	char *expire_time_string = NULL;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	apr_size_t bytes_written;

	if (! get_cache_filename(config, r, &cachefilename))
		return -1;

	if (apr_file_open(&cachefile, cachefilename, APR_READ|APR_WRITE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) 
		return -1;   

	/* skip URL field */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);

	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* calculate new expire_time */
	expire_interval = (int) strtol(buffer, NULL, 10);
	expire_time = apr_time_sec(r->request_time) + expire_interval;
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

int receive_status_line(cache_state_t *cachestate, apr_socket_t *socket)
{
	const char *read_string;
	const char *http_string, *status_string;
	int status = 0;

	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;

	read_string = connection_read_string(socket, r, &status);
	if (read_string == NULL) {
		httpresponse->response = status;
		return status;
	}

	http_string = ap_getword_white(r->pool, &read_string);
	status_string = ap_getword_white(r->pool, &read_string);
	
	httpresponse->response = atoi(status_string);

	return httpresponse->response;
}

static const char* wodan_date_canon(apr_pool_t *p, 
		const char *input_date_string)
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
static void adjust_dates(cache_state_t *cachestate)
{
	const char* datestr = NULL;
	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;

	if ((datestr = apr_table_get(httpresponse->headers, "Date")) != NULL)
		apr_table_set(httpresponse->headers, "Date", wodan_date_canon(r->pool, datestr));
	if ((datestr = apr_table_get(httpresponse->headers, "Last-Modified")) != NULL)
		apr_table_set(httpresponse->headers, "Last-Modified", wodan_date_canon(r->pool, datestr));
	if ((datestr = apr_table_get(httpresponse->headers, "Expires")) != NULL)
		apr_table_set(httpresponse->headers, "Expires", wodan_date_canon(r->pool, datestr));
}


int receive_headers(cache_state_t *cachestate, apr_socket_t *socket)
{
	const char *read_header;
	char *header; // only used as a workaround for when read_header is
	// not big enough to store the incoming header, for
	// example with large Set-Cookie headers
	char *key, *val;
	int val_pos, len, status = 0;
	
	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;

	header = 0;
	while((read_header = connection_read_string(socket, r, &status))) {
		/* if read_header is NULL, this signals an error. Escape from here right
		 * away in that case */
		if (read_header == NULL) {
			httpresponse->response = status;
			return status;
		}

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

		key = ap_getword(r->pool, header ? (const char **)&header: &read_header, ':');
		val = apr_pstrdup(r->pool, header ? header : read_header);
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
		apr_table_add(httpresponse->headers, key, val);
		free(header);
		DEBUG("Added response header: [%s: %s]", key, val);
	}
	/* adjust headers */
	ap_reverseproxy_clear_connection(r->pool, httpresponse->headers);
	adjust_dates(cachestate);
	httpresponse->headers = apr_table_overlay(r->pool, r->err_headers_out, 
			httpresponse->headers);

	return OK;
}

int receive_body(cache_state_t *cachestate, apr_socket_t *socket, apr_file_t *cache_file)
{
	char *buffer;
	int nr_bytes_read;
	int writtenbytes;
	int body_bytes_written;
	int backend_read_error, client_write_error, cache_write_error;

	wodan_config_t *config = cachestate->config;
	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;

	buffer = apr_pcalloc(r->pool, BUFFERSIZE);

	body_bytes_written = 0;
	backend_read_error = 0;
	client_write_error = 0;
	cache_write_error = 0;

	while(1)
	{
		nr_bytes_read = connection_read_bytes(socket, r, buffer, BUFFERSIZE);

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
					
		if (!r->header_only) {
			writtenbytes = ap_rwrite(buffer, nr_bytes_read, r);
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
		
		user_agent = apr_table_get(r->headers_in, "User-Agent");
		if (user_agent == NULL)
			user_agent = "unknown";
		content_length_str = apr_table_get(httpresponse->headers,
						  "Content-Length");
		content_length = (content_length_str) ? 
			atoi(content_length_str): 0;
					
		ERROR("Error writing to client. " 
				"Bytes written/total bytes = %d/%d, " 
				"User-Agent: %s", body_bytes_written, content_length, user_agent);
		return HTTP_BAD_GATEWAY;
	}

	if (cache_write_error) {
		ERROR("Error writing to cache file");
		ap_rflush(r);
		return HTTP_BAD_GATEWAY;
	}

	if (backend_read_error) {
		ERROR("Error reading from backend");
		return HTTP_BAD_GATEWAY;
	}
	
	/* everything went well. Close cache file and make sure
	 * all content goes to the client */
	cache_close_cachefile(config, r, cache_file);
	ap_rflush(r);

	return OK;
}
/**
 * send request line and Host header
 * @param connection connection struct
 * @param r request record
 * @param dest_path destination path
 * @param modified_time set 'If-Modified-Since'-header 
 * @retval -1 on error.
 */
static int send_request(apr_socket_t *socket, 
			request_rec *r, const char *dest_host,
			const char *dest_path, apr_time_t modified_time);



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
			  char **dest_host,
			  int *dest_port, char **dest_path,
			  char **dest_host_and_port,
			  int *do_ssl) 
{
	apr_uri_t uptr;
	char *tmp_path;
	int uri_parse_retval;
	
	if ((uri_parse_retval = apr_uri_parse(p, proxy_url, &uptr)) != APR_SUCCESS) {
		return uri_parse_retval;
	}
	
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
	  /* tmp_path is "/" or longer, always ending in '/'. We need to
	   * strip this / */
	  if (tmp_path[(int) strlen(tmp_path) - 1] == '/') 
		  tmp_path[(int) strlen(tmp_path) - 1] = '\0';
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
	int result;

	if ((result = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)))
		return result;
	
	if (ap_should_client_block(r)) {
		int nr_bytes_read;
		char buffer[BUFFERSIZE];

		while ((nr_bytes_read = ap_get_client_block(r, buffer, BUFFERSIZE)) > 0) { 
			if (connection_write_bytes(socket, r, buffer, nr_bytes_read) == -1) 
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

static void add_x_headers(const request_rec *r,
		   apr_table_t *out_headers_to_backend)
{
	const char *temp;

	/* Add X-Forwarded-For so the backend can find out where the 
	 * request came from. If there's already a X-Forwarded-For
	 * header, the remote_ip is added to that header */
	apr_table_mergen(out_headers_to_backend, "X-Forwarded-For",
			r->connection->remote_ip);
	/* With X-Forwarded-Host, the backend can determine the original
	 * Host: header send to Wodan */
	if ((temp = apr_table_get(r->headers_in, "Host"))) 
		apr_table_mergen(out_headers_to_backend, "X-Forwarded-Host",
				temp);
	/* Add this server (the server Wodan runs on) as the X-Forwarded-Server,
	   The backend can determine the frontend servername by this. */
	apr_table_mergen(out_headers_to_backend, "X-Forwarded-Server",
			r->server->server_hostname);
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
 * @param modified_time last modified time in cache
 */

static int send_complete_request(cache_state_t *cachestate, apr_socket_t *socket,
		const char *dest_host_and_port, const char *dest_path, apr_table_t *out_headers)
{
	int result;
	request_rec *r = cachestate->r;
	apr_time_t modified_time = cachestate->cache_file_time;

	if(send_request(socket, r, dest_host_and_port, dest_path, modified_time) < 0)
		return -1;
	add_x_headers(r, out_headers);
	apr_table_set(out_headers, "Connection", "close");
	apr_table_unset(out_headers, "Via");
	if (send_headers(socket, r, out_headers) == -1)
		return -1;

	if((result = send_request_body(socket, r)))
		return result;
	
	return OK;
}

static int send_request(apr_socket_t *socket, request_rec *r,
		const char *dest_host_and_port, const char *dest_path, apr_time_t modified_time) {
	const char *request_string;
	const char *host_header_string;
	
	request_string = apr_psprintf(r->pool, "%s %s HTTP/1.0%s",
				     r->method, dest_path, CRLF);
	if (connection_write_string(socket, r, request_string) == -1)
		return -1;
	host_header_string = apr_psprintf(r->pool, "Host: %s%s",
					 dest_host_and_port, CRLF);
	if (connection_write_string(socket, r, 
				    host_header_string) == -1)
		return -1;
	if (modified_time != APR_DATE_BAD) {
		char if_modified_header_value[APR_RFC822_DATE_LEN];
		const char *if_modified_header;
		if (apr_rfc822_date(&(if_modified_header_value[0]), modified_time) !=
			APR_SUCCESS) 
			return -1;
			
		if_modified_header = apr_psprintf(r->pool, "If-Modified-Since: %s%s",
				if_modified_header_value, CRLF);
		
		if (connection_write_string(socket, r, if_modified_header) == -1)
			return -1;
	} 
	return OK;
}

static int send_headers(apr_socket_t *socket, request_rec *r, const apr_table_t *headers) 
{
	int i;
	const char* header_end_string;
	
	const apr_array_header_t *headers_array = apr_table_elts(headers);
	apr_table_entry_t *headers_elts = (apr_table_entry_t *) headers_array->elts;
	for (i = 0; i < headers_array->nelts; i++) {
		const char *header_string;
		/* the following headers should not be sent to the
		   backend. */
		if(headers_elts[i].key == NULL || 
		   headers_elts[i].val == NULL || 
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
	header_end_string = apr_psprintf(r->pool, "%s", CRLF);
	if (connection_write_string(socket, r,
				    header_end_string) == -1)
		return -1;

	return OK;
}
       
/** receive the whole response from the backend 
 * @param connection connection to backend
 * @param r request_rec
 * @param httpresponse will hold response
 * @return OK if finished
 */
static int receive_complete_response(cache_state_t *cachestate, apr_socket_t *socket)
{
	int status = OK;
	int receive_headers_result;
	int receive_body_result;
	apr_file_t *cache_file = NULL;

	httpresponse_t *httpresponse = cachestate->httpresponse;

	if ((status = receive_status_line(cachestate, socket)) == -1) {
		httpresponse->response = HTTP_BAD_GATEWAY;
		return HTTP_BAD_GATEWAY;
	}
	
	if (ap_is_HTTP_SERVER_ERROR(status)) { /* = 50x */
		httpresponse->response = HTTP_BAD_GATEWAY;
		return status;
	}

	if (status == HTTP_NOT_MODIFIED) {
		httpresponse->response = status;
		return status;
	}
	
	if ((receive_headers_result = receive_headers(cachestate, socket))) {
		httpresponse->response = HTTP_BAD_GATEWAY;
		return receive_headers_result;
	}
	
	switch(status) {
		case HTTP_OK:
		case HTTP_NOT_FOUND: 
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_MOVED_TEMPORARILY:
		case HTTP_SEE_OTHER:
			cache_file = cache_get_cachefile(cachestate);
			break;
		default:
			cache_file = (apr_file_t *)NULL;
			break;
	}

	adjust_headers_for_sending(cachestate);
	
	if ((receive_body_result = receive_body(cachestate, socket, cache_file))) {
		httpresponse->response = HTTP_BAD_GATEWAY;
		return receive_body_result;
	}

	return status;
}
static apr_socket_t* connection_open (cache_state_t *cachestate, char* host, int port, int do_ssl UNUSED)
{
	apr_socket_t *socket;
	apr_sockaddr_t *server_address;
	wodan_config_t *config = cachestate->config;
	request_rec *r = cachestate->r;
	
	DEBUG("Looking up host %s", host);
	if (apr_sockaddr_info_get(&server_address, host, APR_UNSPEC, port, 0, r->pool) != APR_SUCCESS) {
		ERROR("Hostname lookup failure for: %s", host);
		return NULL;
	}
	
	if (apr_socket_create(&socket, APR_INET, SOCK_STREAM, APR_PROTO_TCP,  r->pool) != APR_SUCCESS) {
		ERROR("Error creating socket");
		return NULL;
	}

	if (config->backend_timeout > 0) {
		apr_socket_timeout_set(socket, config->backend_timeout);
		ERROR("socket timeout set to %ld", config->backend_timeout);
	}
	if (apr_socket_connect(socket, server_address) != APR_SUCCESS) {
		ERROR("Socket error while connecting to server at %s:%d", host, port);
		return NULL;
	}
	DEBUG("Succesfully connected to %s:%d", host, port);

	return socket;
}

static wodan_proxy_destination_t* destination_longest_match(cache_state_t *cachestate)
{
	wodan_proxy_destination_t *longest, *list;
	wodan_config_t *config = cachestate->config;
	char *uri = cachestate->r->unparsed_uri;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan_proxy_destination_t *) config->proxy_passes->elts;
	for(i=0; i < config->proxy_passes->nelts; i++)
	{
		int l = (int) strlen(list[i].path);

		if(l > length && strncmp(list[i].path, uri, l) == 0) {
			longest = &list[i];
			length = l;
		}
	}
	return longest;	
}

int cache_update (cache_state_t *cachestate)
{
	request_rec *r = cachestate->r;
	httpresponse_t *httpresponse = cachestate->httpresponse;

	int result = OK;
	char *desthost, *destpath;
	char *dest_host_and_port;
	int destport;
	int do_ssl;
	apr_pool_t* p = r->pool;
	apr_table_t *out_headers;
	apr_socket_t *socket;

	wodan_proxy_destination_t *proxy;

	if (! (proxy = destination_longest_match(cachestate)))
		return DECLINED;

	int l = (int) strlen(proxy->path);
	char *uri = &(r->unparsed_uri[l - 1]);

	if (get_destination_parts(p, proxy->url, uri, &desthost, &destport,
				  &destpath, &dest_host_and_port,
				  &do_ssl)) {
		ERROR("failed to parse proxy_url %s and uri %s", proxy->url, uri);
		return DECLINED;
	}
		
	DEBUG("Destination: %s %d %s", desthost, destport, destpath);
	
	//Connect to proxyhost
	socket = connection_open(cachestate, desthost, destport, do_ssl);
	if(socket == NULL) {
		httpresponse->response = HTTP_BAD_GATEWAY;
		return HTTP_BAD_GATEWAY;
	}

	//Copy headers and make adjustments
	out_headers = apr_table_copy(r->pool, r->headers_in);
	ap_reverseproxy_clear_connection(p, out_headers);
	
	/* send request */
	if (send_complete_request(cachestate, socket, dest_host_and_port, destpath, out_headers) == -1) {
		apr_socket_close(socket);
		httpresponse->response = HTTP_BAD_GATEWAY;
		return HTTP_BAD_GATEWAY;
	}	
	
	result = receive_complete_response(cachestate, socket);

	apr_socket_close(socket);

	return result;
}

//EOF
