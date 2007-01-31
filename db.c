
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
#include "access.h"
#include "sysstr.h"
#include "md5.h"

#include <stdio.h>
#include <stdlib.h>

#define MAX_BUSY_TRIES 10

static sqlite3* s_db_handle = NULL;
static sqlite3_stmt* s_check_file_stmt = NULL;

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

  rc = sqlite3_exec(s_db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }
}

static void
calc_md5(const struct mystr* p_data_str, struct mystr* p_hash_str)
{
	md5_state_t state;
	md5_byte_t digest[16];
	char hex_output[16*2 + 1];
	int di;

  /* Calculate md5 hash of the password */
	md5_init(&state);
	md5_append(&state, (const md5_byte_t*) str_getbuf(p_data_str), 
             str_getlen(p_data_str));
	md5_finish(&state, digest);
	for (di = 0; di < 16; ++di)
	    sprintf(hex_output + di * 2, "%02x", digest[di]);  
	str_alloc_text(p_hash_str, hex_output);
}

void
vsf_db_open()
{ 
  int rc = sqlite3_open(VSFTP_DB_FILENAME, &s_db_handle);
  if (rc)
  {
    sqlite3_close(s_db_handle);
    die2("unable to open sqlite database: ", 
      sqlite3_errmsg(s_db_handle));
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
  rc = sqlite3_exec(s_db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
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
  rc = sqlite3_exec(s_db_handle, sqlbuf, cb_get_session_list,
    (void*) p_str, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
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
  rc = sqlite3_exec(s_db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }
  
  long long int rowid = sqlite3_last_insert_rowid(s_db_handle);
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

  rc = sqlite3_exec(s_db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
  }
 
}

void
vsf_db_close()
{
  if (s_check_file_stmt != NULL)
    sqlite3_finalize(s_check_file_stmt);
  sqlite3_close(s_db_handle);
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
  struct mystr hash_str = INIT_MYSTR;
  
  if (str_isempty(p_user_str) || str_isempty(p_pass_str))
    return 0;

  /* Calculate md5 hash of the password */
  calc_md5(p_pass_str, &hash_str);
    
  str_alloc_text(&sql_str,
    "select id from vsf_user where enabled = 1 and name = '");
  str_append_str(&sql_str, p_user_str);
  str_append_text(&sql_str, "' and password = '");
  str_append_str(&sql_str, &hash_str);
  str_append_text(&sql_str, "'");

  const char* sqlbuf = str_getbuf(&sql_str);
  int uid = -1;
  rc = sqlite3_exec(s_db_handle, sqlbuf, cb_auth, (void*) &uid, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
    return 0;
  }

  if (uid == -1)
    return 0;
    
  /* Set the user ID */
  p_sess->user_id = uid;
    
  /* IP check */
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
  rc = sqlite3_exec(s_db_handle, sqlbuf, cb_ipcheck, (void*) &ipvalid,
                    &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
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
  rc = sqlite3_exec(s_db_handle, sqlbuf, NULL, NULL, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
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
  rc = sqlite3_exec(s_db_handle, sqlbuf, cb_ipcheck, (void*) &valid, &sql_err);
  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    sqlite3_close(s_db_handle);
    die2("sql error: ", sql_err); /* Exit */
    /* sqlite3_free(sql_err); */
    return 0;
  }

  return valid;
}


int vsf_db_check_file(const struct vsf_session* p_sess,
                      const struct mystr* p_filename_str,
                      enum EVSFFileAccess what)
{
  static struct mystr sql_str = INIT_MYSTR;
  static struct mystr path_str = INIT_MYSTR;
  int rc = 0;
  int busy_count = 0;
  int perm = 0;
  int final_perm = 0;
  int col = 0;
  const char* p_tail = NULL;

  if (s_check_file_stmt == NULL)
  {
    /* Build the SQL statement */
    str_alloc_text(&sql_str, 
      "select f_view, f_get, f_put, f_resume, f_delete, f_rename"
      "  d_view, d_change, d_list, d_create, d_delete, d_rename "
      " from vsf_section s, vsf_section_perm p"
      " where s.id = p.section_id and ? glob s.path and"
      "   (p.user_id = ? or p.group_id in ("
      "     select g.id from vsf_group g, vsf_member m"
      "       where g.id = m.group_id and m.user_id = ?)"
      "   ) order by s.priority desc, length(s.path) desc");
  
    rc = sqlite3_prepare_v2(s_db_handle, str_getbuf(&sql_str), -1,
                            &s_check_file_stmt, &p_tail);
    if (rc != SQLITE_OK)
      die("vsf_db_check_file(): unable to prepare statement");
  }

  /* Build the full path */
  str_getcwd(&path_str);
  str_append_text(&path_str, "/");
  str_append_str(&path_str, p_filename_str);

  /* Path */
  rc = sqlite3_bind_text(s_check_file_stmt, 1, str_getbuf(&path_str), -1,
                    SQLITE_STATIC);
  if (rc != SQLITE_OK)
    die("vsf_db_check_file(): unable to bind parameter");

  /* User ID */
  rc = sqlite3_bind_int(s_check_file_stmt, 2, p_sess->user_id);
  if (rc != SQLITE_OK)
    die("vsf_db_check_file(): unable to bind parameter");

  /* User ID again */
  rc = sqlite3_bind_int(s_check_file_stmt, 3, p_sess->user_id);
  if (rc != SQLITE_OK)
    die("vsf_db_check_file(): unable to bind parameter");

  /* Now we execute the SQL statement. Handle the possibility that
     sqlite is busy, but drop out after a number of attempts. */
  int step = 1;
  while (step)
  {
    /* Execute the statement */
    rc = sqlite3_step(s_check_file_stmt);

    switch (rc)
    {
      case SQLITE_BUSY:    /*We must try again, but not forever.*/
        if (busy_count++ > MAX_BUSY_TRIES)
          die("vsf_db_check_file(): db locked");
        vsf_sysutil_sleep(0);  /*For a gentler poll.*/
        break;

      case SQLITE_DONE:    /*Success, leave the loop */
        step = 0;
        break;

      case SQLITE_ROW:     /*A row is ready.*/
        /* Make sure the column order in the SQL statement is the same! */
        switch (what)
        {
          case kVSFFileView:   col = 0;  break;
          case kVSFFileGet:    col = 1;  break;
          case kVSFFilePut:    col = 2;  break;
          case kVSFFileResume: col = 3;  break;
          case kVSFFileDelete: col = 4;  break;
          case kVSFFileRename: col = 5;  break;          
          case kVSFDirView:    col = 6;  break;
          case kVSFDirChange:  col = 7;  break;
          case kVSFDirList:    col = 8;  break;
          case kVSFDirCreate:  col = 9;  break;
          case kVSFDirDelete:  col = 10; break;        
          
          case kVSFFileChmod:
            bug("vsf_db_check_file(): chmod is not a valid acl permission");
            return 0;
        }

        perm = sqlite3_column_int(s_check_file_stmt, col);
        switch (perm)
        {
          case 0:    /* Not set, inherited from parent */
            break;

          case 1:    /* Implicit allow */
            final_perm = 1;
            break;

          case -1:   /* Explicit deny, abort loop on first occurrance */
            final_perm = 0;
            step = 0;
            break;

          default:
            bug("vsf_db_check_file(): invalid permission value in database");
        }
        break;

      case SQLITE_ERROR:   /*Run time error, discard the VM.*/
   		  die2("vsf_db_check_file(): sqlite error ",
             sqlite3_errmsg(s_db_handle));  /*Fatal DB Error.*/
        break;

      case SQLITE_MISUSE:  /*VM should not have been used.*/
    		die("vsf_db_check_file(): sqlite misuse");  /*Fatal DB Error.*/
        break;

      default:
        die("vsf_db_check_file(): unexpected result");  /*Fatal DB Error.*/
        break;
    }  /*switch*/
  }    /*while*/

  sqlite3_reset(s_check_file_stmt);
  str_free(&sql_str);
  str_free(&path_str);
  return final_perm;
}


int vsf_db_change_password(const struct vsf_session* p_sess,
                           const struct mystr* p_user_str,
                           const struct mystr* p_pass_str)
{ 
  (void) p_sess;

  static struct mystr hash_str = INIT_MYSTR;
  static struct mystr sql_str = INIT_MYSTR;
  sqlite3_stmt* p_stmt = NULL;
  int rc;
  const char* p_tail = NULL;
  int busy_count = 0;

  /* Calculate a MD5 hash */
  calc_md5(p_pass_str, &hash_str);
  
  str_alloc_text(&sql_str, "update vsf_user set password = ? where name = ?");
  rc = sqlite3_prepare_v2(s_db_handle, str_getbuf(&sql_str), -1, 
                          &p_stmt, &p_tail);
  if (rc != SQLITE_OK)
      die("vsf_db_change_password(): unable to prepare statement");
      
  /* Password */
  rc = sqlite3_bind_text(p_stmt, 1, str_getbuf(&hash_str), -1, SQLITE_STATIC);
  if (rc != SQLITE_OK)
    die("vsf_db_change_password(): unable to bind parameter");

  /* Username */
  rc = sqlite3_bind_text(p_stmt, 2, str_getbuf(p_user_str), -1, SQLITE_STATIC);
  if (rc != SQLITE_OK)
    die("vsf_db_change_password(): unable to bind parameter");
  
  /* Now we execute the SQL statement. Handle the possibility that
     sqlite is busy, but drop out after a number of attempts. */
  int step = 1;
  while (step)
  {
    rc = sqlite3_step(p_stmt);

    switch (rc)
    {
      case SQLITE_BUSY:    /*We must try again, but not forever.*/
        if (busy_count++ > MAX_BUSY_TRIES)
          die("vsf_db_check_file(): db locked");
        vsf_sysutil_sleep(0);  /*For a gentler poll.*/
        break;

      case SQLITE_DONE:    /*Success, leave the loop */
        step = 0;
        break;

      case SQLITE_ROW:     /*A row is ready.*/
        break;

      case SQLITE_ERROR:   /*Run time error, discard the VM.*/
   		  die2("vsf_db_check_file(): sqlite error ",
             sqlite3_errmsg(s_db_handle));  /*Fatal DB Error.*/
        break;

      case SQLITE_MISUSE:  /*VM should not have been used.*/
    		die("vsf_db_check_file(): sqlite misuse");  /*Fatal DB Error.*/
        break;

      default:
        die("vsf_db_check_file(): unexpected result");  /*Fatal DB Error.*/
        break;
    }  /*switch*/
  }    /*while*/

  sqlite3_finalize(p_stmt); 
  return sqlite3_changes(s_db_handle);
}                           

#endif
