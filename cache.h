/** $Id: cache.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */

#ifndef CACHE_H
#define CACHE_H

#include "datatypes.h"

/**
 * This is used when allocating buffers to work with
 */
#define MAX_CACHEFILE_PATH_LENGTH 512

/**
 * used for signaling if a URI is present in the cache
 */
typedef enum {
	WODAN_CACHE_PRESENT,        /** present and fresh */
	WODAN_CACHE_PRESENT_EXPIRED,/** present but expired */
	WODAN_CACHE_NOT_PRESENT,     /** not present */
	WODAN_CACHE_NOT_CACHEABLE,   /** cannot be cached */
	WODAN_CACHE_404              /** cached 404 */
} WodanCacheStatus_t;

/**
 * Look wether or not the request can be handled from the cache
 * @param r the request record
 * @param config the wodan configuration
 * @param[out] cache_file_time the time the cache file was created.
 * @return
 *      - WODAN_CACHE_PRESENT if present and fresh
 *      - WODAN_CACHE_PRESENT_EXPIRED if present but expired
 *      - WODAN_CACHE_NOT_PRESENT not present in cache 
 *      - WODAN_CACHE_NOT_CACHEABLE for requests that cannot be cached
 *      - WODAN_CACHE_404 for requests that are cached as a 404 (not found)
 */
WodanCacheStatus_t cache_status(cache_state_t *);

/**
 * Look whether the request can be handled from the cache.
 * @param r The request record
 * @param config the wodan configuration 
 * @param httpresponse The httpresponse record the data should be set in
 * @return 1 of request can be handled from cache 0 otherwise
 */
int cache_read(cache_state_t *);

/**
 * Method that connects to the backend and gets data from it
 * @param host The ReverseProxyPass url
 * @param httpresponse The httpresponse structure to put the data in
 * @param r The request record
 * @param cache_file_time creation time of cache file (or (time_t) 0 if there's
 * 		no cache file.
 * @return The result code returned by the backend
 * 
 */
int cache_update(cache_state_t *);


/**
 * get cache file
 * @param r request_rec
 * @param config the wodan configuration
 * @param httpresponse the httpresponse from the backend
 * @retval NULL if not being cached
 * @retval apr_file_t pointer otherwise.
 */
apr_file_t *cache_get_cachefile(cache_state_t *);

/**
 * close the cache file.
 * @param r request_rec
 * @param config the wodan configuration
 * @param cachefile the cache file, may be NULL
 */
void cache_close_cachefile(wodan_config_t *config, request_rec *r, 
	apr_file_t *cachefile);

/**
 * update the timestamp in the cache file 
 * @param r request_rec
 * @param config the wodan configuration
 */
int cache_update_expiry_time(cache_state_t *);
#endif
