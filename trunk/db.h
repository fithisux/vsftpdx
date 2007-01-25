#ifndef VSF_DB_H
#define VSF_DB_H

#include "logging.h"
#include "session.h"

int
vsf_db_open();

void
vsf_db_close();

int
vsf_db_check_auth(struct vsf_session* p_sess,
                  const struct mystr* p_user_str,
                  const struct mystr* p_pass_str,
                  const struct mystr* p_remote_host);

void
vsf_db_log(struct vsf_session* p_sess,
           int succeeded,
           enum EVSFLogEntryType what,
           const struct mystr* p_str);

void
vsf_db_get_session_list(struct mystr* p_str);

void
vsf_db_add_session(struct vsf_session* p_sess);

void
vsf_db_del_session(struct vsf_session* p_sess);

void
vsf_db_cleanup();

#endif /* VSF_DB_H */
