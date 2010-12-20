/**
 * (c) 2000-2006 IC&S, The Netherlands
 * (c) 2008-2011 NFG, The Netherlands
 * @file util.c
 *
 * Implements different utility functions that are used by Wodan
 */
 
#include "datatypes.h"
#include "util.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include "apr_date.h"
#include "apr_file_info.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_user.h"

#ifndef APR_HAS_USER
#define APR_HAS_USER
#endif

#define SECONDS_IN_MINUTE 60
#define SECONDS_IN_HOUR (60 * SECONDS_IN_MINUTE)
#define SECONDS_IN_DAY (24 * SECONDS_IN_HOUR)
#define SECONDS_IN_WEEK (7 * SECONDS_IN_DAY)

/**
 * debug instrumentation
 */

#define LOGFORMAT "%s: %s"

void wodan_trace(request_rec *r, int level, const char *file, int line, const char *func, const char *formatstring, ...)
{
	va_list ap, cp;
	char *message = NULL;
	va_start(ap, formatstring);
	va_copy(cp, ap);
	message = apr_pvsprintf(r->pool, formatstring, cp);
	va_end(cp);

	ap_log_error(file, line, level, 0, r->server, LOGFORMAT, func, message);

}
/**
 * Copy key/data pair of overlay only if that key is not set for base.
 *
 * Note that there exists no apr method exactly like this one.
 */
static void wodan_table_add_when_empty(apr_table_t *base, apr_table_t *overlay);

/**
 * apply "proxy pass reverse". This changes all "Location", "URI",
 * and "Content-Location" headers to the one configured in the config file
 * @param config wodan configuration
 * @param headers current headers (received from backend)
 * @param r request record (new headers will be placed here)
 */ 
void apply_proxy_pass_reverse(wodan_config_t *config, apr_table_t* headers,
	request_rec *r);

/** 
 * do reverse mapping of location. 
 */
const char* wodan_location_reverse_map(wodan_proxy_alias_t* alias, const char *url,
	request_rec *r);
/**
 * checks if the user wodan is running as (e.g. 'nobody') is owner of the
 * file 'path' and also had write access to it.
 */
int util_file_is_writable(apr_pool_t *p, const char *path)
{
	apr_finfo_t file_info;
	apr_uid_t user_id;
	apr_gid_t group_id;
	
	apr_stat(&file_info, path, APR_FINFO_USER | APR_FINFO_GROUP | APR_FINFO_PROT, p);
	apr_uid_current(&user_id, &group_id, p);
	
	if (file_info.protection & APR_UWRITE)
	 	return 1;
	 return 0;
}

int util_string_is_number(const char *the_string)
{
	while (*the_string != '\0')
		if (!apr_isdigit(*(the_string++)))
			return 0;
	return 1;
}

apr_int32_t util_timestring_to_seconds(char *string)
{
	
	char *character;
	apr_int32_t number = 0;

	if (string == NULL)		
		return 0;

	character = string;
	
	/* calculate number */
	while (apr_isdigit(*character) || apr_isspace(*character)) {
		if (apr_isdigit(*character)) {
			/* translate to number */
			unsigned digit = (unsigned) *character - (unsigned) '0';
			ap_assert(digit < 10);
			number = (number * (apr_int32_t) 10) + (apr_int32_t) digit; 
		}
		character += 1;
	}
	
	if (*character != '\0') {
		switch(*character) {
			case 'w':
			case 'W':
				number = number * SECONDS_IN_WEEK;
				break;
			case 'd':
			case 'D':
				number = number * SECONDS_IN_DAY;
				break;
			case 'h':
			case 'H':
				number = number * SECONDS_IN_HOUR;
				break;
			case 'm':
			case 'M':
				number = number * SECONDS_IN_MINUTE;
				break;
			case 's':
			case 'S':
			default:
				/* this is only here for clarity */
				number = number;
				break;
		}
	}
	
	if (number > MAX_CACHE_TIMEOUT)
		number = MAX_CACHE_TIMEOUT;
	return number;
}

char* util_skipspaces (char* input)
{
	while(*input == ' ')
		input++;
	return input;
}

void adjust_headers_for_sending(wodan_config_t *config, request_rec *r, 
	httpresponse_t *httpresponse)
{
	/* do more adjustments to the headers. This used to be in 
	   mod_reverseproxy.c */
	apr_table_unset(httpresponse->headers, "X-Wodan");
	wodan_table_add_when_empty(httpresponse->headers, r->headers_out);
	apply_proxy_pass_reverse(config, httpresponse->headers, r);
	
	r->headers_out = httpresponse->headers;
	r->content_type = apr_table_get(httpresponse->headers, "Content-Type");
	r->status = httpresponse->response;
}

/* 
 * Copy key/data pair of overlay only if that key is not set for base.
 *
 * Note that there exists no apr method exactly like this one.
 */
void wodan_table_add_when_empty(apr_table_t *base, apr_table_t *overlay)
{
	const apr_array_header_t *overlay_array = apr_table_elts(overlay);
	apr_table_entry_t *elts = (apr_table_entry_t *)overlay_array->elts;
	int i;
	
	for (i = 0; i < overlay_array->nelts; ++i) 
		if(!apr_table_get(base, elts[i].key))
			apr_table_add(base, elts[i].key, elts[i].val);
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
void apply_proxy_pass_reverse(wodan_config_t *config, apr_table_t* headers,
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

const char* wodan_location_reverse_map(wodan_proxy_alias_t* alias, const char *url,
	request_rec *r)
{
	int url_len;
	int alias_len;
	
	url_len = strlen(url);
	alias_len = strlen(alias->alias);
	DEBUG("Replacing %s with %s", url, alias->alias);
	if (url_len >= alias_len && strncmp(alias->alias, url, alias_len) == 0) {
		char *constructed_url, *result;
		constructed_url = apr_pstrcat(r->pool, alias->path, &url[alias_len], NULL);
		result = ap_construct_url(r->pool, constructed_url, r);
		DEBUG("Replacing with %s", result);
		return (const char *)result;
	}
	else return url;

}
const char* wodan_date_canon(apr_pool_t *p, 
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
