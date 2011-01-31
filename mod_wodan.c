/* 
 * (c) 2000-2006 IC&S, The Netherlands
 * (c) 2008-2010 NFG, The Netherlands
 */ 

#define WODAN_NAME "Wodan"
#define WODAN_VERSION "2.0.1"

/* constants identifying the source of the returned (to the client) object */
#define LOG_SOURCE_CACHED "Cached"
#define LOG_SOURCE_BACKEND "Backend"
#define LOG_SOURCE_CACHED_BACKEND_ERROR "CachedBackendError"

/* local includes */
#include "cache.h"
#include "datatypes.h"
#include "httpclient.h"
#include "util.h"

/* Apache includes */
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_date.h"
#include <string.h>
#include <time.h>

module AP_MODULE_DECLARE_DATA wodan_module;

static void *wodan_create_config(apr_pool_t *p)
{
	wodan_config_t* config = (wodan_config_t *) apr_pcalloc(p, sizeof(wodan_config_t));
	
	config->cachedir_levels           = DEFAULT_CACHEDIR_LEVELS;
	config->proxy_passes              = apr_array_make(p, 0, sizeof(wodan_proxy_destination_t));
	config->proxy_passes_reverse      = apr_array_make(p, 0, sizeof(wodan_proxy_alias_t));
	config->default_cachetimes        = apr_array_make(p, 0, sizeof(wodan_default_cachetime_t));
	config->default_cachetimes_regex  = apr_array_make(p, 0, sizeof(wodan_default_cachetime_regex_t));
	config->default_cachetimes_header = apr_array_make(p, 0, sizeof(wodan_default_cachetime_header_t));	
	config->hash_headers              = apr_array_make(p, 0, sizeof(const char *));
	config->hash_headers_match        = apr_array_make(p, 0, sizeof(wodan_hash_header_match_t));
	return config;		
}

static void *wodan_create_server_config(apr_pool_t *p, server_rec *s UNUSED)
{
	return wodan_create_config(p);
}

static void *wodan_create_dir_config(apr_pool_t *p, char *dir UNUSED)
{
	return wodan_create_config(p);
}
	          
static void *wodan_merge_config(apr_pool_t *p, void *base_config_p, void *new_config_p)
{
	wodan_config_t *config      = (wodan_config_t *) apr_pcalloc(p, sizeof(wodan_config_t));
	wodan_config_t *base_config = (wodan_config_t *) base_config_p;
	wodan_config_t *new_config  = (wodan_config_t *) new_config_p;
	
	if (strlen(new_config->cachedir) > 0) 
		apr_cpystrn(config->cachedir, new_config->cachedir, MAX_CACHE_PATH_SIZE + 1);
	else 
		apr_cpystrn(config->cachedir, base_config->cachedir, MAX_CACHE_PATH_SIZE + 1);
	
	config->cachedir_levels = new_config->cachedir_levels;
	if (new_config->is_cachedir_set == 1 || base_config->is_cachedir_set == 1)
		config->is_cachedir_set = 1;
	if (new_config->run_on_cache == 1 || base_config->run_on_cache == 1)
		config->run_on_cache = 1;
	if (new_config->cache_404s == 1 || base_config->cache_404s == 1)
		config->cache_404s = 1;
	if (new_config->backend_timeout != (apr_interval_time_t) 0)
		config->backend_timeout = new_config->backend_timeout;
	else
		config->backend_timeout = base_config->backend_timeout;
		
	config->proxy_passes = apr_array_append(p, base_config->proxy_passes, new_config->proxy_passes);
	config->proxy_passes_reverse = apr_array_append(p, base_config->proxy_passes_reverse, new_config->proxy_passes_reverse);
	config->default_cachetimes = apr_array_append(p, base_config->default_cachetimes, new_config->default_cachetimes);
	config->default_cachetimes_regex = apr_array_append(p, base_config->default_cachetimes_regex, new_config->default_cachetimes_regex);
	config->default_cachetimes_header = apr_array_append(p, base_config->default_cachetimes_header, new_config->default_cachetimes_header);
	config->hash_headers = apr_array_append(p, base_config->hash_headers, new_config->hash_headers);
	config->hash_headers_match = apr_array_append(p, base_config->hash_headers_match, new_config->hash_headers_match);

	return config;
}               


static const char *add_pass(cmd_parms *cmd, void *dummy UNUSED, 
	const char *path, const char *url)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(s->module_config, &wodan_module);
	wodan_proxy_destination_t *proxy_destination;
	char *proxy_url;
	
	if(path[0] != '/' || path[(int) strlen(path) - 1] != '/')
	        return "First argument of WodanPass should be a dir e.g. /dir/";
	if (strncasecmp(url, "http://", 7) != 0)
		return "Second argument of WodanPass should be a http:// url";
	
	proxy_url = apr_pstrdup(cmd->pool, url);
	/* strip final '/' of proxy_url */
	if (proxy_url[(int) strlen(proxy_url) - 1] == '/')
		proxy_url[(int) strlen(proxy_url) - 1] = '\0';
	
	proxy_destination = apr_array_push(config->proxy_passes);
	proxy_destination->path = path;
	proxy_destination->url = proxy_url;
	return NULL;
}

static const char *add_pass_reverse(cmd_parms *cmd,
	void *dummy UNUSED, const char *path, const char *url)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(s->module_config, &wodan_module);
	wodan_proxy_destination_t *proxy_alias;
	
	if(path[0] != '/' || path[(int) strlen(path) - 1] != '/')
	        return "First argument of WodanPassReverse should be a dir e.g. /dir/";
	if ((strncasecmp(url, "http://", 7) != 0) && (strncasecmp(url, "https://", 8) != 0))
		return "Second argument of WodanPassReverse should be a http:// or https:// url";
	
	proxy_alias = apr_array_push(config->proxy_passes_reverse);
	proxy_alias->path = path;
	proxy_alias->url = url;
	return NULL;
}

static const char *add_cachedir(cmd_parms *cmd, void *dummy UNUSED, 
	const char *path)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(s->module_config, &wodan_module);
	
	/* prepend server root path */
	const char *fname = ap_server_root_relative(cmd->pool, path);
	
	if (!ap_is_directory(cmd->pool, fname))
		return apr_psprintf(cmd->pool, "WodanCacheDir %s is not a directory!", fname);
	
	if (!util_file_is_writable(cmd->pool, fname))
		return apr_psprintf(cmd->pool, "WodanCachedir %s should be owned by Wodan user and should be writable by that user!", fname);
	
	apr_cpystrn(config->cachedir, fname, MAX_CACHE_PATH_SIZE + 1);
	config->is_cachedir_set = 1;
	
	return NULL;
}	

static const char *add_cachedir_levels(cmd_parms *cmd, void *dummy UNUSED, const char *level)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(s->module_config, &wodan_module);
	apr_int64_t levels;

	if (!util_string_is_number(level))
		return apr_psprintf(cmd->pool, "Argument to WodanCacheDirLevels should be a number, it is %s now", level);
	
	levels = apr_strtoi64(level, NULL, 10);

	if (levels < 0 || levels > (apr_int64_t) MAX_CACHEDIR_LEVELS)
		return apr_psprintf(cmd->pool, "WodanCacheDirLevels must have a value between 0 and %d", (int) MAX_CACHEDIR_LEVELS);
	
	config->cachedir_levels = (int) levels;
	return NULL;
}	

static const char *add_default_cachetime(cmd_parms *cmd, 
	void *dummy UNUSED, const char *path, const char *time_string)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(s->module_config, &wodan_module);
	wodan_default_cachetime_t *new_default_cachetime;
	
	if (path[0] != '/' || path[(int) strlen(path) - 1] != '/')
		return "First argument of WodanDefaultCacheTime should be a path, e.g. /dir/";
	 
	new_default_cachetime = apr_array_push(config->default_cachetimes);
	new_default_cachetime->path = path;
	if (strncmp(time_string, "no", 2 ) == 0 )
		new_default_cachetime->cachetime = (apr_int32_t)-1;
	else { 
	 	new_default_cachetime->cachetime = util_timestring_to_seconds(apr_pstrdup(cmd->pool, time_string));
	}
	return NULL;
}

static const char* add_default_cachetime_regex(cmd_parms *cmd, 
	void *dummy UNUSED, const char *regex_pattern, 
	const char *time_string)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(s->module_config, &wodan_module);
	wodan_default_cachetime_regex_t *new_default_cachetime_regex;
	ap_regex_t *compiled_pattern = NULL;

	new_default_cachetime_regex = apr_array_push(config->default_cachetimes_regex);
	
	compiled_pattern = ap_pregcomp(cmd->pool, regex_pattern, AP_REG_EXTENDED | AP_REG_NOSUB);
	if (compiled_pattern == NULL)
		return apr_psprintf(cmd->pool, "Failure compiling regex pattern \"%s\"", regex_pattern);

	new_default_cachetime_regex->uri_pattern = compiled_pattern;
	
	if (strncmp(time_string, "no", 2) == 0)
		new_default_cachetime_regex->cachetime = (apr_int32_t) -1;
	else
		new_default_cachetime_regex->cachetime = util_timestring_to_seconds(apr_pstrdup(cmd->pool, time_string));

	return NULL;
}

static const char* add_hash_header(cmd_parms *cmd, void *dummy UNUSED, const char *headername)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *) ap_get_module_config(s->module_config, &wodan_module);

	*(const char **)apr_array_push(config->hash_headers) = headername;

	return NULL;
}

static const char* add_hash_header_match(cmd_parms *cmd, 
	void *dummy UNUSED, const char *headername, const char *regex_pattern, const char *replacement)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *) ap_get_module_config(s->module_config, &wodan_module);
	ap_regex_t *compiled_pattern = NULL;
	wodan_hash_header_match_t *directive;

	compiled_pattern = ap_pregcomp(cmd->pool, regex_pattern, AP_REG_EXTENDED);
	if (compiled_pattern == NULL)
		return apr_psprintf(cmd->pool, "Failure compiling regex pattern \"%s\"", regex_pattern);

	directive = apr_array_push(config->hash_headers_match);
	directive->header = apr_pstrdup(cmd->pool, headername);
	directive->regex = compiled_pattern;
	directive->pattern = apr_pstrdup(cmd->pool, replacement);
	
	return NULL;
}

static const char* add_default_cachetime_header(cmd_parms *cmd, 
	void *dummy UNUSED, const char *http_header, 
	const char *regex_pattern, const char *time_string)
{
	server_rec *s = cmd->server;
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(s->module_config, &wodan_module);
	wodan_default_cachetime_header_t *new_default_cachetime_header;
	ap_regex_t *compiled_pattern;
	
	new_default_cachetime_header = apr_array_push(config->default_cachetimes_header);
	new_default_cachetime_header->header = apr_pstrdup(cmd->pool, http_header);
	compiled_pattern = ap_pregcomp(cmd->pool, regex_pattern, AP_REG_EXTENDED | AP_REG_NOSUB);
	if (compiled_pattern == NULL)
		return apr_psprintf(cmd->pool, "Failure compiling regex pattern \"%s\"", regex_pattern);

	new_default_cachetime_header->header_value_pattern = compiled_pattern;
	if (strncmp(time_string, "no", 2) == 0) 
		new_default_cachetime_header->cachetime = (apr_int32_t) -1;
	else
		new_default_cachetime_header->cachetime = util_timestring_to_seconds(apr_pstrdup(cmd->pool, time_string));
			
	return NULL;
}

static const char* add_run_on_cache(cmd_parms *cmd, void *dummy UNUSED, int flag)
{
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(cmd->server->module_config, &wodan_module);
      
	config->run_on_cache = (unsigned) flag;
	
	return NULL;
}

static const char *add_cache_404s(cmd_parms *cmd, 
	void *dummy UNUSED, int flag)
{
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(cmd->server->module_config, &wodan_module);
	
	config->cache_404s = (unsigned) flag;
	
	return NULL;
}

static const char *add_backend_timeout(cmd_parms *cmd,
	void *dummy UNUSED, const char *timeout_string)
{
	wodan_config_t *config = (wodan_config_t *)ap_get_module_config(cmd->server->module_config, &wodan_module);
	apr_int64_t timeout;
	
	if (!util_string_is_number(timeout_string))
		return apr_psprintf(cmd->pool, "argument should be number, it is \"%s\" now", timeout_string);

	timeout = apr_strtoi64(timeout_string, NULL, 10);
	
	// timeout is a number in milliseconds, so it needs to be multiplied by 1000
	timeout *= 1000;
	
	if (timeout > apr_time_from_sec(MAX_BACKEND_TIMEOUT_SEC))
		config->backend_timeout = apr_time_from_sec(MAX_BACKEND_TIMEOUT_SEC);
	else
		config->backend_timeout = timeout;
	
	return NULL;
}

static wodan_proxy_destination_t* destination_longest_match(wodan_config_t *config, 
	char *uri)
{
	wodan_proxy_destination_t *longest, *list;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan_proxy_destination_t *) config->proxy_passes->elts;
	for(i=0; i < config->proxy_passes->nelts; i++)
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


static int wodan_init_handler(apr_pool_t *p, 
	apr_pool_t *plog UNUSED, 
	apr_pool_t *ptemp UNUSED,
	server_rec *s UNUSED)
{
	const char *identifier_string;
	
	identifier_string = apr_psprintf(p, "%s/%s", WODAN_NAME, WODAN_VERSION);
	ap_add_version_component(p, identifier_string);
	
	return OK;
}
static int wodan_handler(request_rec *r)
{
	int response = HTTP_BAD_GATEWAY;
	wodan_config_t* config;
	httpresponse_t httpresponse;
	WodanCacheStatus_t cache_status;
	apr_time_t cache_file_time;
	const char *ifmodsince;
	wodan_proxy_destination_t *proxy_destination;
	
	config = (wodan_config_t *)ap_get_module_config(r->server->module_config, &wodan_module);
	
	if (! (proxy_destination = destination_longest_match(config, r->unparsed_uri)))
		return DECLINED;

	DEBUG("Processing new request: %s%s", r->hostname, r->unparsed_uri);

	// see if the request can be handled from the cache.
	cache_status = cache_get_status(config, r, &cache_file_time);

	DEBUG("cache_get_status: %d cache404s: %s", cache_status, config->cache_404s?"On":"Off");

	memset(&httpresponse, 0, sizeof(httpresponse_t));
	httpresponse.headers = apr_table_make(r->pool, 0);

	if ((config->cache_404s) && (cache_status == WODAN_CACHE_404)) {
	  	cache_read_from_cache(config, r, &httpresponse);
		DEBUG("Return cached 404");
		return HTTP_NOT_FOUND;
	}
	
	if (cache_status != WODAN_CACHE_PRESENT) {
		/* attempt to get data from backend */

		char* newpath;
		int l = (int) strlen(proxy_destination->path);
		newpath = &(r->unparsed_uri[l - 1]);

		//Get the httpresponse from remote server	
		response = http_proxy(config, proxy_destination->url, newpath, &httpresponse, r, cache_file_time);

		DEBUG("http_proxy returned: %d", response);

		/* If 404 are to be cached, then already return
		 * default 404 page here in case of a 404. */
		if ((config->cache_404s) && (response == HTTP_NOT_FOUND)) {
			DEBUG("returning: %d", response);
			return HTTP_NOT_FOUND;
		}
		/* if nothing can be received from backend, and there's
		   nothing in cache, return the response code so
		   ErrorDocument can handle it ... */
		if (((response == HTTP_NOT_FOUND) || ap_is_HTTP_SERVER_ERROR(response)) && (cache_status != WODAN_CACHE_PRESENT_EXPIRED)) {
			if (config->run_on_cache)
				response = HTTP_NOT_FOUND;
			DEBUG("returning: %d", response);
			return response;
		} 

	}

	if (cache_status == WODAN_CACHE_PRESENT) {
		if ((ifmodsince = apr_table_get(r->headers_in, "If-Modified-Since"))) {
			apr_time_t if_modified_since;
			if ((if_modified_since = apr_date_parse_http(ifmodsince))) {
				if (cache_file_time <= if_modified_since) {
					DEBUG("returning: 304");
					return HTTP_NOT_MODIFIED;
				}
			}
		}
	  	cache_read_from_cache(config, r, &httpresponse);
	} else if (cache_status == WODAN_CACHE_PRESENT_EXPIRED && (ap_is_HTTP_SERVER_ERROR(response) || (response == HTTP_NOT_MODIFIED))) {
	  	cache_read_from_cache(config, r, &httpresponse);
		cache_update_expiry_time(config, r);
	}

	//Return some response code
	DEBUG("httpresponse.response: %d",  httpresponse.response);
	
	return OK; 
}

static void wodan_register_hooks(apr_pool_t *p UNUSED)
{
	ap_hook_post_config(wodan_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(wodan_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec wodan_commands[] = 
{
	AP_INIT_TAKE12("WodanPass", add_pass, NULL, RSRC_CONF, "A path and a URL"),
	AP_INIT_TAKE12("WodanPassReverse", add_pass_reverse, NULL, RSRC_CONF, "A path and a URL"),
	AP_INIT_TAKE1("WodanCacheDir", add_cachedir, NULL, RSRC_CONF, "A path"),
	AP_INIT_TAKE1("WodanCacheDirLevels", add_cachedir_levels, NULL, RSRC_CONF, "A Number (> 0)"),
	AP_INIT_TAKE2("WodanDefaultCacheTime", add_default_cachetime, NULL, RSRC_CONF, "A path and a time string"),
	AP_INIT_TAKE2("WodanDefaultCacheTimeMatch", add_default_cachetime_regex, NULL, RSRC_CONF, "A regex pattern and a time string"),
	AP_INIT_TAKE3("WodanDefaultCacheTimeHeaderMatch", add_default_cachetime_header, NULL, RSRC_CONF, "A header, a regex pattern and a time string"),
	AP_INIT_TAKE1("WodanHashHeader", add_hash_header, NULL, RSRC_CONF, "A header to add to the hash"),
	AP_INIT_TAKE23("WodanHashHeaderMatch", add_hash_header_match, NULL, RSRC_CONF, "A header to add to the hash if the regex pattern matches and an optional replacement pattern"),
	AP_INIT_FLAG("WodanRunOnCache", add_run_on_cache, NULL, RSRC_CONF, "run completely on cache"),
	AP_INIT_FLAG("WodanCache404s", add_cache_404s, NULL, RSRC_CONF, "cache 404 pages"),
	AP_INIT_TAKE1("WodanBackendTimeout", add_backend_timeout, NULL, RSRC_CONF, "a number, which represents a time in miliseconds"),
	{NULL}
};


module AP_MODULE_DECLARE_DATA wodan_module = {
    STANDARD20_MODULE_STUFF, 
    wodan_create_dir_config,   /* create per-dir    config structures */
    wodan_merge_config,        /* merge  per-dir    config structures */
    wodan_create_server_config,/* create per-server config structures */
    wodan_merge_config,        /* merge  per-server config structures */
    wodan_commands,            /* table of config file commands       */
    wodan_register_hooks       /* register hooks                      */
};



