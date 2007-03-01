#ifndef VSF_DB_H
#define VSF_DB_H

#include "logging.h"
#include "session.h"
#include "access.h"

/* vsf_db_open()
 * PURPOSE
 * Opens the database file. If any error occurs the process terminates.
 */
void vsf_db_open();

/* vsf_db_close()
 * PURPOSE
 * Closes the database file.
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

/* vsf_db_get_session_list()
 * PURPOSE
 * Returns the list of active sessions (connected clients) as a string.
 * PARAMETERS
 * p_str        - The result string containing the session list on success.
 */
void vsf_db_get_session_list(struct mystr* p_str);


/* Vsf_db_add_session()
 * PURPOSE
 * Adds a new entry to the session table.
 * PARAMETERS
 * p_sess       - The session
 */
void vsf_db_add_session(struct vsf_session* p_sess);


/* vsf_db_del_session()
 * PURPOSE
 * Deletes an existing session from the database.
 * PARAMETERS
 * p_sess        - The session
 */
void vsf_db_del_session(struct vsf_session* p_sess);


/* vsf_db_cleanup()
 * PURPOSE
 * Deletes temporary data from the database. Cleaned tables: vsf_session.
 */
void vsf_db_cleanup();


/* vsf_db_check_remote_host()
 * PURPOSE
 * Checks if a remote host is allowed to connect by comparing its IP address
 * with all entries in the user database. If it matches any IP mask of any
 * user the connection is allowed.
 * PARAMETERS
 * p_remote_host   - the IP address of the remote host
 * RETURNS
 * 1 if the IP is valid, otherwhise 0.
 */
int vsf_db_check_remote_host(const struct mystr* p_remote_host);


/* vsf_db_check_file()
 * PURPOSE
 * Checks the access permissions for the given file or directory.
 * PARAMETERS
 * p_sess          - the current session
 * p_filename_str  - the file or directory to check
 * what            - the requested permission
 * RETURNS
 * 1 if the access is granted, otherwise 0.
 */
int vsf_db_check_file(const struct vsf_session* p_sess,
                      const struct mystr* p_filename_str,
                      enum EVSFFileAccess what);

/* vsf_db_change_password()
 * PURPOSE
 * Changes the password of the given user in the database.
 * PARAMETERS
 * p_sess          - the current session
 * p_user_str      - user name
 * p_pass_str      - new password
 * RETURNS
 * 1 if the password was changed, otherwise 0.
 */
int vsf_db_change_password(const struct vsf_session* p_sess,
                           const struct mystr* p_user_str,
                           const struct mystr* p_pass_str);
                                                                                                      
/* vsf_db_check_credit()
 * PURPOSE
 * Checks the user has enough credit for a requested download.
 * PARAMETERS
 * p_sess          - the current session
 * p_filename_str  - the path used to detect the section
 * amount          - required credit in bytes
 * RETURNS
 * 1 if the user has enough credit, otherwise 0.
 */
int vsf_db_check_credit(const struct vsf_session* p_sess, 
                        const struct mystr* p_filename_str,
                        const filesize_t amount);
                        
/* vsf_db_update_credit()
 * PURPOSE
 * Increases or decreases the credit of the current user.
 * PARAMETERS
 * p_sess          - the current session
 * p_filename_str  - the path used to detect the section
 * upload          - 1 = upload (inc credit), 0 = download (dec credit)
 * amount          - credit delta in bytes
 * RETURNS
 * 1 if the update was successful, otherwise 0.
 */
int vsf_db_update_credit(const struct vsf_session* p_sess, 
                         const struct mystr* p_filename_str,
                         const int upload,
                         const filesize_t amount);

/* vsf_db_get_infoline()
 * PURPOSE
 * Creates a string with section, credit and ratio information which is shown
 * at the end of a directory listing.
 * PARAMETERS
 * p_sess          - the current session
 * p_dirname_str   - the path used to detect the section
 * p_infoline_str  - result (output variable)
 * RETURNS
 */
void vsf_db_get_infoline(const struct vsf_session* p_sess,
                         const struct mystr* p_dir_name_str,
                         struct mystr* infoline_str);

                         
int vsf_db_add_user(const struct vsf_session* p_sess,
                    const struct mystr* p_user_str);
                    
int vsf_db_remove_user(const struct vsf_session* p_sess,
                       const struct mystr* p_user_str);
                       
int vsf_db_change_user(const struct vsf_session* p_sess,
                       const struct mystr* p_user_str,
                       const struct mystr* p_attr_str,
                       const struct mystr* p_value_str);
#endif /* VSF_DB_H */
