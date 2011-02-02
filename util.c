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


