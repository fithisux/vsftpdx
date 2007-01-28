#ifndef VSF_DB_H
#define VSF_DB_H

#include "logging.h"
#include "session.h"
#include "access.h"

/* vsf_db_open()
 * PURPOSE
 * Opens the database file. If any error occurs the process terminates.
 * PARAMETERS
 * RETURNS
 */
void vsf_db_open();


/* vsf_db_close()
 * PURPOSE
 * Closes the database file.
 * PARAMETERS
 * RETURNS
 */
void vsf_db_close();


/* vsf_db_check_auth()
 * PURPOSE
 * Checks the authentication of the given user.
 * PARAMETERS
 * p_sess        - The current session
 * p_user_str    - User name provided by the client
 * p_pass_str    - Password provided by the client
 * p_remote_host - IP address of the remote host as string
 * RETURNS
 * 1 if the authentication is valid, 0 otherwise
 */
int vsf_db_check_auth(struct vsf_session* p_sess, 
                      const struct mystr* p_user_str,
                      const struct mystr* p_pass_str,
                      const struct mystr* p_remote_host);


/* vsf_db_log()
 * PURPOSE
 * Adds a new log entry to the database.
 * PARAMETERS
 * p_sess       - The current session
 * succeeded    - Determines if the operation was a success (1) or not (0)
 * what         - The type of the log entry (defined in an enum)
 * p_str        - Custom text
 */
void vsf_db_log(struct vsf_session* p_sess, int succeeded,
                enum EVSFLogEntryType what, const struct mystr* p_str);

void vsf_db_get_session_list(struct mystr* p_str);

void vsf_db_add_session(struct vsf_session* p_sess);

void vsf_db_del_session(struct vsf_session* p_sess);

void vsf_db_cleanup();

/* vsf_db_check_remote_host()
 * PURPOSE
 * Checks if a remote host is allowed to connect by comparing its IP address
 * with all entries in the user database. If it matches any IP mask of any
 * user the connection is allowed.
 * PARAMETERS
 * p_remote_host   - the IP address of the remote host
 * RETURNS
 * 1 if the IP is valid, otherwhise 0
 */
int vsf_db_check_remote_host(const struct mystr* p_remote_host);

/* vsf_db_check_file()
 * PURPOSE
 * Checks the access permissions for the given file or directory.
 */
int vsf_db_check_file(const struct vsf_session* p_sess,
                      const struct mystr* p_filename_str,
                      enum EVSFFileAccess what);
                      
#endif /* VSF_DB_H */
