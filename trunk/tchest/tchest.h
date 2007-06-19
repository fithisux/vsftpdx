
#ifndef TCHEST_H
#define TCHEST_H

#define TCH_MAXLEN_PATH     255
#define TCH_MAXLEN_USERNAME 64
#define TCH_MAXLEN_HOST     64

#define filesize_t long long

/* Session management -------------------------------------------------------*/

struct tch_session
{
  int id;   /* Session ID */
  int uid;  /* User ID */
  int pid;  /* Process ID for multiprocess servers */
  char cwd[TCH_MAXLEN_PATH];
  char username[TCH_MAXLEN_USERNAME];
  char remotehost[TCH_MAXLEN_HOST];
};

void
tch_session_init(
  struct tch_session* session
);

int
tch_session_add(
  struct tch_session* session
);

int
tch_session_remove(
  struct tch_session* session
);

int
tch_session_getlist(
  struct tch_session** list,
  const int maxlen,
  int* len
);


/* Misc --------------------------------------------------------------------*/

enum {
  TCH_OPEN_OK,
  TCH_OPEN_ERR_SQLITE,
  TCH_OPEN_ERR_LUA
};

int
tch_open(
  const char* dbfile, 
  const char* scriptdir
);

int
tch_close();

const char*
tch_errmsg();


/* Checks -------------------------------------------------------------------*/

enum {
  TCH_AUTH_OK,
  TCH_AUTH_BADPASS,
  TCH_AUTH_BADHOST,
  TCH_AUTH_ERR_DB,
  TCH_AUTH_ERR_PARAM,
};


/* Checks the authentication of the user using the specified username and
 * password and the remote host of the connection. Optionally the ident
 * (RFC1413) is validated.
 */
int
tch_check_auth(
  struct tch_session* session, 
  const char* username,
  const char* password,
  const char* host, 
  const char* ident
);


enum
{
  TCH_HOST_OK,
  TCH_HOST_ERR_NOUSER,
  TCH_HOST_ERR_BLOCKED
};

/* Checks if a remote host is allowed to connect by comparing its IP address
 * with all entries in the user database. If it matches any IP mask of any
 * user the connection is allowed.
 */
int
tch_check_host(
  const char* host
);

enum
{
  TCH_PERM_GRANTED,
  TCH_PERM_DENIED 
};

enum
{
  TCH_PERM_FILE_VIEW = 1, /* See the file */
  TCH_PERM_FILE_GET,      /* Download a file */
  TCH_PERM_FILE_PUT,      /* Upload a file */  
  TCH_PERM_FILE_RESUME,   /* Resume an upload */
  TCH_PERM_FILE_DELETE,   /* Delete a file */
  TCH_PERM_FILE_RENAME,   /* Rename a file */
  TCH_PERM_FILE_CHMOD,    /* Change local filesystem permissions */
  TCH_PERM_DIR_VIEW,      /* See directory */
  TCH_PERM_DIR_LIST,      /* List directory content */
  TCH_PERM_DIR_CHANGE,    /* Change into the directory */
  TCH_PERM_DIR_CREATE,    /* Create sub directory */
  TCH_PERM_DIR_DELETE,    /* Delete sub directory */
};

int
tch_check_fileperm(
  const struct tch_session* session,
  const char* filename,
  int what
);


/* Credit management --------------------------------------------------------*/
enum {
  TCH_CREDIT_OK,
  TCH_CREDIT_INSUFFICIENT 
};

int
tch_credit_check (
  /* The current session */
  const struct tch_session* session,
  
  /* Full path to the requested file */
  const char* filename,
  
  /* Size of the (remaining) file */
  const filesize_t amount
);


enum
{
  TCH_CREDIT_ADD,
  TCH_CREDIT_REMOVE,
  TCH_CREDIT_SET
};

int
tch_credit_update(
  const struct tch_session* session,
  const char* filename,
  const int type,
  const filesize_t amount
);


/* Log ----------------------------------------------------------------------*/

enum {
  TCH_LOG_OK,
  TCH_LOG_ERR_DB 
};

enum {
  TCH_LOG_NULL = 1,
  TCH_LOG_DOWNLOAD,
  TCH_LOG_UPLOAD,
  TCH_LOG_MKDIR,
  TCH_LOG_LOGIN,
  TCH_LOG_FTP_INPUT,
  TCH_LOG_FTP_OUTPUT,
  TCH_LOG_CONNECTION,
  TCH_LOG_DELETE,
  TCH_LOG_RENAME,
  TCH_LOG_RMDIR,
  TCH_LOG_CHMOD
};

int
tch_log_append(
  const struct tch_session* session,
  const int succeeded,
  const int what,
  const char* message,
  const char* path,
  const long long duration,
  const long long size
);

/* User management ----------------------------------------------------------*/

enum
{
  TCH_UID_UNKNOWN = -1,
  TCH_UID_ROOT = 0
};

enum
{
  TCH_GID_UNKNOWN = -1 
};

int
tch_user_add(
  const struct tch_session* session,
  const char* username,
  int* uid
);

int
tch_user_remove(
  const struct tch_session* session,
  const int uid,
  const char* username
);

int
tch_user_change(
  const struct tch_session* session,
  const int uid,
  const char* username,
  const char* key,
  const char* value
);


/* Group management ---------------------------------------------------------*/

enum
{
  TCH_GROUP_OK, 
  TCH_GROUP_ERR_PERM
};


int 
tch_group_add(
  const struct tch_session* session,
  const char* groupname,
  int* gid
);


int 
tch_group_remove(
  const struct tch_session* session,
  int gid, 
  const char* groupname
);


int 
tch_group_change(
  const struct tch_session* session,
  const int gid, 
  const char* groupname,
  const char* key,
  const char* value
);



int 
tch_group_join(
  /* The current session */
  const struct tch_session* session, 
  
  /* Group ID, -1 if groupname is specified */
  const int gid,
  
  /* Group name, NULL if group ID is specified */
  const char* groupname,

  /* ID of the user which is added to the group */
  const int uid
);


int 
tch_group_leave(
  const struct tch_session* session,
  const int gid, 
  const char* groupname, 
  const int uid
);


/* FTP command hooks --------------------------------------------------------*/

enum
{
  TCH_FTP_OK,
  TCH_FTP_NOTHANDLED,
  TCH_FTP_ABORT,
  TCH_FTP_ERR  
};

enum
{
  TCH_FTP_PRE,
  TCH_FTP_POST,
  TCH_FTP_SITE 
};

/* Indicates if the FTP command is handled */
int 
tch_ftp_ishandled(
  const char* command,
  const int type
);


/* Executes the FTP command */
int
tch_ftp_execute(
  const struct tch_session* session,
  const char* command,
  const int type,
  int* resultcode,
  const char* resulttext
);

#endif /* TCHEST_H */
