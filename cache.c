/** $Id: cache.c 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */

#include <sys/stat.h>
#include <string.h>
#include <assert.h>

#include "cache.h"
#include "datatypes.h"
#include "util.h"

#include "httpd.h"
#include "http_log.h"
#include "apr.h"
#include "apr_date.h"
#include "apr_sha1.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_time.h"

#include <string.h>

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

WodanCacheStatus_t cache_get_status(wodan_config_t *config, request_rec *r, apr_time_t *cache_file_time)
{
	char* cachefilename;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int status;
	int interval_time = 0;
	long int ttl;

	*cache_file_time = (apr_time_t) 0;

	if(r->method_number != M_GET && !r->header_only)
		return WODAN_CACHE_NOT_CACHEABLE;

	// if the CacheDir directive is not set, we cannot read from cache
	if (!is_cachedir_set(config))
		return WODAN_CACHE_NOT_PRESENT;

	if (! get_cache_filename(config, r, &cachefilename))
		return WODAN_CACHE_NOT_CACHEABLE;

	if (apr_file_open(&cachefile, cachefilename, APR_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
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
		*cache_file_time = cachefile_expire_time - apr_time_from_sec(interval_time);
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
						*cache_file_time = last_modified;
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

int cache_read_from_cache (wodan_config_t *config, request_rec *r, struct httpresponse* httpresponse)
{
	char* cachefilename;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int write_error;
	int content_length = 0;
	int body_bytes_written = 0;
	
	if (! get_cache_filename(config, r, &cachefilename))
		return 0;

	apr_file_open(&cachefile, cachefilename, APR_READ, APR_OS_DEFAULT, r->pool);
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
		apr_file_remove(cachefilename, r->pool);
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
	adjust_headers_for_sending(config, r, httpresponse);

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
	DEBUG("%s OK content-length: %d, body_bytes: %d", cachefilename, content_length, body_bytes_written);

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

apr_file_t *cache_get_cachefile(wodan_config_t *config, request_rec *r, 
	struct httpresponse *httpresponse)
{
	apr_file_t *cache_file = NULL;
	char *expire = NULL;
	int expire_interval = 0;
	char *tempfile_template;
	char *temp_dir;	
	
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

int cache_update_expiry_time(wodan_config_t *config, request_rec *r) 
{
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

//EOF
