#ifndef VSF_DEFS_H
#define VSF_DEFS_H

#define VSFTP_DEFAULT_CONFIG    "/etc/vsftpd.conf"

#define VSFTP_COMMAND_FD        0

#define VSFTP_PASSWORD_MAX      128
#define VSFTP_USERNAME_MAX      32
#define VSFTP_MAX_COMMAND_LINE  4096
#define VSFTP_DATA_BUFSIZE      65536
#define VSFTP_DIR_BUFSIZE       16384
#define VSFTP_PATH_MAX          4096
#define VSFTP_CONF_FILE_MAX     100000
#define VSFTP_LISTEN_BACKLOG    32
#define VSFTP_SECURE_UMASK      077
#define VSFTP_ROOT_UID          0
/* Must be greater than both VSFTP_MAX_COMMAND_LINE and VSFTP_DIR_BUFSIZE */
#define VSFTP_PRIVSOCK_MAXSTR   VSFTP_DIR_BUFSIZE

#define VSFTP_DB_FILENAME         "site.db"

#endif /* VSF_DEFS_H */

