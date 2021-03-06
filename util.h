/*
 * (c) 2000-2006 IC&S, The Netherlands
 * (c) 2008-2012 NFG, The Netherlands, paul@nfg.nl
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include "datatypes.h"

#include "httpd.h"
#include "http_protocol.h"

void wodan_trace(request_rec *r, int level, const char *file, int line, const char *func, const char *formatstring, ...) PRINTF_ARGS(6,7);

/**
 * determines if a file or directory is writable
 * @param p memory pool
 * @param path the path to check
 * @retval 1 if writable
 * @retval 0 if not writable
 */
int util_file_is_writable(apr_pool_t *p, const char *path);

/**
 * determines if a string is a number (contains only digits)
 * @param the_string
 * @retval 1 if it is a number
 * @retval 0 if it's not a number
 * @note make sure the string is NUL-terminated!
 */
int util_string_is_number(const char *the_string);

/**
 * translates the string to seconds. The string can be of the format:
 * [0-9]*[wWdDhHmMsS]{0,1}
 * Where w/W is Week, d/D is day, h/H is hour, m/M is minute, s/S is second.
 * The number before the modifier will be multiplied by the number of seconds
 * in a week/day/hour/minute/second. Without a modifier, the number is in seconds.
 * @param string the string containing the time.
 * @retval 0 if not parsable.
 * @retval MAX_CACHE_TIMEOUT if number too big
 * @retval number of seconds otherwise.
 */
apr_int32_t util_timestring_to_seconds(char *string);

/**
 * Walk the pointer and skip all spaces
 * @param input The char*
 * @return A char* to the result location after skipping all spaces
 */
char* util_skipspaces (char* input);


#endif //_UTIL_H_
