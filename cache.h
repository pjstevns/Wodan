/** $Id: cache.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 * (c) 2008-2011, NFG Net Facilities Group BV, info@nfg.nl
 */

#ifndef CACHE_H
#define CACHE_H

#include "datatypes.h"
#include "http_config.h"

#define T CacheState_T
typedef struct T *T;

extern T cache_new(request_rec *r, module *);
extern int cache_handler(T);
extern int cache_status(T C);
extern int cache_update(T C);
extern int cache_read(T C);

#undef T
#endif
