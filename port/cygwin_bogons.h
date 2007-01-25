#ifndef VSF_CYGWIN_BOGONS_H
#define VSF_CYGWIN_BOGONS_H

/* Needed for Cygwin NT authentication */
#include <pwd.h>
#include <windows.h>
#include <sys/cygwin.h>
#define is_winnt                (GetVersion() < 0x80000000)

/* Cygwin's root UID is that of the LocalSystem account (i.e., 18) */
#undef VSFTP_ROOT_UID
#define VSFTP_ROOT_UID  18
#define VSFTP_ROOT_GID  0
#define VSFTP_ADMIN_GID 544

/* Not supported on standard cygwin */
#undef VSF_BUILD_IPV6

#endif /* VSF_CYGWIN_BOGONS_H */
