#ifndef VSF_SYSDEPUTIL_H
#define VSF_SYSDEPUTIL_H

#ifndef VSF_FILESIZE_H
#include "filesize.h"
#endif

#ifndef VSF_SESSION_H
#include "session.h"
#endif

/* VSF_SYSDEPUTIL_H:
 * Support for highly system dependent features, and querying for support
 * or lack thereof
 * TODO: document functions!
 */

struct mystr;

/* Authentication of local users */
/* Return 0 for fail, 1 for success */
int vsf_sysdep_check_auth(struct vsf_session* p_sess,
                          const struct mystr* p_user,
                          const struct mystr* p_pass,
                          const struct mystr* p_remote_host);

/* Support for fine grained privilege (capabilities) */
int vsf_sysdep_has_capabilities(void);
int vsf_sysdep_has_capabilities_as_non_root(void);
void vsf_sysdep_keep_capabilities(void);
enum ESysdepCapabilities
{
  kCapabilityCAP_CHOWN = 1,
  kCapabilityCAP_NET_BIND_SERVICE = 2
  /* NOTE - next one will be 4, this is a bitfield */
};
void vsf_sysdep_adopt_capabilities(unsigned int caps);

/* Support for sendfile(), Linux-like interface. Collapses to a read/write
 * loop under the covers if the target system lacks support.
 */
int vsf_sysutil_sendfile(const int out_fd, const int in_fd,
                         filesize_t* p_offset, filesize_t num_send,
                         unsigned int max_chunk);

/* Support for changing the process name as reported by the operating system.
 * A useful status monitor. NOTE - we don't guarantee that this call will
 * have any effect.
 */
void vsf_sysutil_setproctitle_init(int argc, const char* argv[]);
void vsf_sysutil_setproctitle(const char* p_text);
void vsf_sysutil_setproctitle_str(const struct mystr* p_str);
void vsf_sysutil_set_proctitle_prefix(const struct mystr* p_str);

/* For now, maps read/write private pages. API to be extended.. */
void vsf_sysutil_map_anon_pages_init(void);
void* vsf_sysutil_map_anon_pages(unsigned int length);

/* File descriptor passing/receiving */
void vsf_sysutil_send_fd(int sock_fd, int send_fd);
int vsf_sysutil_recv_fd(int sock_fd);

#endif /* VSF_SYSDEPUTIL_H */

