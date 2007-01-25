#ifndef VSF_PORTINGJUNK_H
#define VSF_PORTINGJUNK_H

#ifdef __sun
#include "solaris_bogons.h"
#endif

#ifdef __sgi
#include "irix_bogons.h"
#endif

#ifdef __hpux
#include "hpux_bogons.h"
#endif

#ifdef _AIX
#include "aix_bogons.h"
#endif

#ifdef __osf__
#include "tru64_bogons.h"
#endif

/* So many older systems lack these, that it's too much hassle to list all
 * the errant systems
 */
#include "cmsg_extras.h"

#ifdef __CYGWIN__
#include "cygwin_bogons.h"
#endif

#endif /* VSF_PORTINGJUNK_H */

