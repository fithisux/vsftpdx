
#include "builddefs.h"

#ifdef VSF_BUILD_SQLITE

#include "sqlite3.h"

#include "str.h"
#include "utility.h"
#include "session.h"
#include "sysutil.h"
#include "logging.h"
#include "rfc1413.h"
#include "tunables.h"
#include "defs.h"

#include <stdio.h>
#include <stdlib.h>

static sqlite3* db_handle;

static int
cb_auth(void* param, int argc, char **argv, char **colnames)
{
  (void) colnames;

  if (argc == 0)
    return 1;

  char* s = argv[0];
  int* uid = (int*) param;
  *uid = atoi(s);
  
  return 0;
}

static int
cb_ipcheck(void* param, int argc, char **argv, char **colnames)
{
  (void) colnames;

  if (argc == 0)
    return 1;

  char* s = argv[0];
  int* valid = (int*) param;
  *valid = atoi(s) > 0 ? 1 : 0;

  return 0;
}

static int
cb_get_session_list(void* param, int argc, char **argv, char **colnames)
{
  (void) colnames;
  if (argc < 3)
    return 1;

  char* id_str        = argv[0];
  char* user_id_str   = argv[1];
  char* remote_ip_str = argv[2];
  
  struct mystr* result_str = (struct mystr*) param;
  struct mystr temp_str = INIT_MYSTR;
  
  // ID
  str_alloc_text(&temp_str, id_str);
  str_rpad(&temp_str, 5);
  str_append_str(result_str, &temp_str);
  
  // User ID
  str_alloc_text(&temp_str, user_id_str);
  str_rpad(&temp_str, 12);
  str_append_str(result_str, &temp_str);
  
  // Remote IP  
  str_alloc_text(&temp_str, remote_ip_str);
  str_rpad(&temp_str, 16);
  str_append_str(result_str, &temp_str);

  str_append_text(result_str, "\r\n");

  str_free(&temp_str);
  return 0;
}

static void
update_last_login(int uid)
{
  int rc = 0;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;

  /* Build the SQL string */
  str_alloc_text(&sql_str,
    "update vsf_user set last_login = current_timestamp where id = ");
  str_append_ulong(&sql_str, uid);
  const char* sqlbuf = str_getbuf(&sql_str);

  rc = sqlite3_exec(db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }
}

void
vsf_db_open()
{ 
  int rc = sqlite3_open(VFS_DB_FILENAME, &db_handle);
  if (rc)
  {
    sqlite3_close(db_handle);
    die2("unable to open sqlite database: ", 
      sqlite3_errmsg(db_handle));
  }  
}

void
vsf_db_log(struct vsf_session* p_sess,
           int succeeded,
           enum EVSFLogEntryType what,
           const struct mystr* p_str)
{
  int rc = 0;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;
  
  long delta_msec = 0;
  if (what == kVSFLogEntryDownload ||
      what == kVSFLogEntryUpload)
  {
    /* Determine the duration in milliseconds */  
    vsf_sysutil_get_current_date(); /* Update date cache */
    
    /* Now */
    long sec = vsf_sysutil_get_cached_time_sec();
    long usec = vsf_sysutil_get_cached_time_usec();
    long now_msec = sec * 1000 + usec > 0 ? (usec / 1000) : 0;
  
    /* Start */
    sec = p_sess->log_start_sec;
    usec = p_sess->log_start_usec;
    long start_msec = sec * 1000 + usec > 0 ? (usec / 1000) : 0;
    
    /* Delta */
    delta_msec = now_msec - start_msec;
    if (delta_msec <= 0)
    {
      delta_msec = 1;
    }
  }
  
  /* Build the SQL string */ 
  str_alloc_text(&sql_str, 
    "insert into vsf_log (event_id, succeeded, user, remote_ip, pid, message,"
    " path, filesize, duration) values(");
  str_append_ulong(&sql_str, what);                          /* Event */
  str_append_text(&sql_str, ",");
  str_append_ulong(&sql_str, succeeded);                     /* Succeeded */
  str_append_text(&sql_str, ",'");
  str_append_str(&sql_str, &p_sess->user_str);               /* User */
  str_append_text(&sql_str, "','");
  str_append_str(&sql_str, &p_sess->remote_ip_str);          /* Remote IP */
  str_append_text(&sql_str, "',");
  str_append_ulong(&sql_str, vsf_sysutil_getpid());          /* PID */
  str_append_text(&sql_str, ",'");
  str_append_str(&sql_str, p_str);                           /* Message */
  str_append_text(&sql_str, "','");
  str_append_str(&sql_str, &p_sess->log_str);                /* Path */
  str_append_text(&sql_str, "',");
  str_append_filesize_t(&sql_str, p_sess->transfer_size);    /* Filesize */
  str_append_text(&sql_str, ",");
  str_append_ulong(&sql_str, delta_msec);                    /* Duration */
  str_append_text(&sql_str, ")");

  const char* sqlbuf = str_getbuf(&sql_str);
  rc = sqlite3_exec(db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }    
}

void
vsf_db_get_session_list(struct mystr* p_str)
{
  int rc = 0;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;

  str_append_text(p_str, "ID   User        IP\r\n");
  
  /* Build the SQL string */ 
  str_alloc_text(&sql_str, 
    "select id, user_id, remote_ip from vsf_session");
  
  const char* sqlbuf = str_getbuf(&sql_str);
  rc = sqlite3_exec(db_handle, sqlbuf, cb_get_session_list, 
    (void*) p_str, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
    return;
  }  
}


void
vsf_db_add_session(struct vsf_session* p_sess)
{
  int rc = 0;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;
  
  /* Build the SQL string */ 
  str_alloc_text(&sql_str, 
    "insert into vsf_session (user_id, remote_ip) values (");
  str_append_ulong(&sql_str, p_sess->user_id);
  str_append_text(&sql_str, ",'");
  str_append_str(&sql_str, &p_sess->remote_ip_str);
  str_append_text(&sql_str, "'");
  str_append_text(&sql_str, ")"); 

  const char* sqlbuf = str_getbuf(&sql_str);
  rc = sqlite3_exec(db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }
  
  long long int rowid = sqlite3_last_insert_rowid(db_handle);
  p_sess->id = (int) rowid;
}

void
vsf_db_del_session(const struct vsf_session* p_sess)
{
  int rc = 0;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;
  
  /* Build the SQL string */ 
  str_alloc_text(&sql_str, 
    "delete from vsf_session where id = ");
  str_append_ulong(&sql_str, p_sess->id);
  const char* sqlbuf = str_getbuf(&sql_str);

  rc = sqlite3_exec(db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }
 
}

void
vsf_db_close()
{
  sqlite3_close(db_handle);
}

int
vsf_db_check_auth(struct vsf_session* p_sess,
                  const struct mystr* p_user_str,
                  const struct mystr* p_pass_str,
                  const struct mystr* p_remote_host)
{                 
  int rc = 0;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;
  struct mystr ident_str = INIT_MYSTR;
  struct mystr log_line_str = INIT_MYSTR;
  
  if (str_isempty(p_user_str) || str_isempty(p_pass_str))
    return 0;

  str_alloc_text(&sql_str,
    "select id from vsf_user where enabled = 1 and name = '");
  str_append_str(&sql_str, p_user_str);
  str_append_text(&sql_str, "' and password = '");
  str_append_str(&sql_str, p_pass_str);  
  str_append_text(&sql_str, "'");

  const char* sqlbuf = str_getbuf(&sql_str);
  int uid = -1;
  rc = sqlite3_exec(db_handle, sqlbuf, cb_auth, (void*) &uid, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
    return 0;
  }

  if (uid == -1)
    return 0;
    
  /* Set the user ID */
  p_sess->user_id = uid;
    
  /* ip check */
  str_alloc_text(&sql_str, "select count(*) from vsf_ipmask where user_id = ");
  str_append_ulong(&sql_str, uid);
  str_append_text(&sql_str, " and '");
  str_append_str(&sql_str, p_remote_host);
  str_append_text(&sql_str, "' glob mask");

  if (tunable_ident_check_enable)
  {
      rc = rfc1413(p_sess->p_remote_addr, p_sess->p_local_addr,
                   &ident_str, tunable_ident_check_timeout);
      if (rc == 0)
      {
        /* The ident check was successful */
        str_append_text(&sql_str, " and (ident isnull or ident = '");
        str_append_str(&sql_str, &ident_str);
        str_append_text(&sql_str, "')");
      }
      else
      {
        /* The ident check failed, the use may only login if no ident is
           required */
        str_append_text(&sql_str, " and ident isnull");

        str_alloc_text(&log_line_str, "Ident check failed.");
        vsf_log_line(p_sess, kVSFLogEntryConnection, &log_line_str);
        str_free(&log_line_str);
      }

      str_free(&ident_str);
  }

  sqlbuf = str_getbuf(&sql_str);
  int ipvalid = 0;
  rc = sqlite3_exec(db_handle, sqlbuf, cb_ipcheck, (void*) &ipvalid, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err);
    /* sqlite3_free(sql_err); */
    return 0;
  }
  
  if (ipvalid)
  {
    vsf_db_add_session(p_sess);
    update_last_login(uid);
    return 1;
  }
    
  return 0;
}

void
vsf_db_cleanup()
{
  int rc;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;
    
  str_alloc_text(&sql_str, "delete from vsf_session");
  const char* sqlbuf = str_getbuf(&sql_str);
  rc = sqlite3_exec(db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }  
}

int
vsf_db_check_remote_host(const struct mystr* p_remote_host)
{
  int rc = 0;
  char* sql_err = 0;
  struct mystr sql_str = INIT_MYSTR;
  
  str_alloc_text(&sql_str,
    "select count(*) from vsf_ipmask where '");
  str_append_str(&sql_str, p_remote_host);
  str_append_text(&sql_str, "' glob mask");

  const char* sqlbuf = str_getbuf(&sql_str);
  int valid = 0;
  rc = sqlite3_exec(db_handle, sqlbuf, cb_ipcheck, (void*) &valid, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
    return 0;
  }

  return valid;
}

#endif
