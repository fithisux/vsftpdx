#ifndef VSF_RFC1413_H
#define VSF_RFC1413_H

#include "sysutil.h"
#include "str.h"

/* Gets the ident string (user name) for a given connection specified by
 * local and remote address. The ident protocol is specified in RFC1413.
 *
 * Warning: Indent checks are completely useless if the connecting users
 * are not on a multiuser UNIX like system or have root access which allows
 * them to return any user name they want. The ident check can provide a
 * minimum of additional security if you can trust the owner of the clients
 * host but not the user.
 */
int
rfc1413(struct vsf_sysutil_sockaddr* p_remote_addr, 
        struct vsf_sysutil_sockaddr* p_local_addr, 
        struct mystr* p_ident_str, int ident_timeout_time);

#endif
