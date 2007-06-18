
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <sqlite3.h>

#include "tchest.h"
#include "md5.h"

#define MAXLEN_SQL    255
#define MAXLEN_ERRMSG 255

/* Static variables ---------------------------------------------------------*/

/* SQLite */
static sqlite3*      s_db_handle               = NULL;
static sqlite3_stmt* s_check_file_stmt         = NULL;
static sqlite3_stmt* s_get_credit_stmt         = NULL;
static sqlite3_stmt* s_update_credit_stmt      = NULL;
static sqlite3_stmt* s_get_credit_section_stmt = NULL;
static sqlite3_stmt* s_get_ratio_stmt          = NULL;
static int           s_busy_count              = 0;
static int           s_step                    = 1;

/* The Lua interpreter */
static lua_State*    s_lua_handle              = NULL;
static char*         s_initpath                = NULL;

static char          s_errmsg[MAXLEN_ERRMSG]   = "";


/* Private function declarations --------------------------------------------*/

/* Sets the static error text */
static void set_errmsg();

/* Calculates an MD5 sum */
static void calc_md5(const char* data, char* hash, const int len);


/* Session management -------------------------------------------------------*/


void
tch_session_init(struct tch_session* session)
{
  memset(session, 0, sizeof(struct tch_session));
}


int
tch_session_add(struct tch_session* session)
{

}

int
tch_session_remove(struct tch_session* session)
{
}

int
tch_session_getlist(struct tch_session** list, const int maxlen, int* len)
{

}

int
tch_open(const char* dbfile, const char* scriptdir)
{
  int rc = sqlite3_open(dbfile, &s_db_handle);
  if (rc)
  {
    set_errmsg(sqlite3_errmsg(s_db_handle));
    return TCH_OPEN_ERR_SQLITE;
  }

}

int
tch_close()
{
 	/* Close Lua */
  if (s_lua_handle != NULL)
  {
  	lua_close(s_lua_handle);
    s_lua_handle = NULL;
  }

  /* Destroy prepared statements */
  if (s_check_file_stmt != NULL)
  {
    sqlite3_finalize(s_check_file_stmt);
    s_check_file_stmt = NULL;
  }
  if (s_get_credit_stmt != NULL)
  {
    sqlite3_finalize(s_get_credit_stmt);
    s_get_credit_stmt = NULL;
  }
  if (s_update_credit_stmt != NULL)
  {
    sqlite3_finalize(s_update_credit_stmt);
    s_update_credit_stmt = NULL;
  }
  if (s_get_credit_section_stmt != NULL)
  {
    sqlite3_finalize(s_get_credit_section_stmt);
    s_get_credit_section_stmt = NULL;
  }

  /* Close the database */
  if (s_db_handle != NULL)
  {
    sqlite3_close(s_db_handle);
    s_db_handle = NULL;
  }
}


int tch_check_auth(const char* username, const char* password,
                   const char* host, int* uid)
{
  int rc = 0;
  char* sql_err = 0;
  static char hash[32 + 1]; /* 128bit MD5 + terminating 0 */
  static char sql[MAXLEN_SQL];

  if (username == NULL || strlen(username) == 0)
    return TCH_AUTH_ERR_BADUSER;

  if (password == NULL || strlen(password) == 0)
  {
    hash[32] = '\0';
  }
  else
  {
    calc_md5(password, hash, sizeof(hash));
  }

  snprintf(sql, MAXLEN_SQL,
    "SELECT id FROM vsf_user WHERE enabled = 1 AND name = '%s'"
    " AND (password = '%s' OR password isnull)",
    username, password);


#ifdef FOO
  int uid = -1;
  rc = sqlite3_exec(s_db_handle, sql, cb_auth, (void*) &uid, &sql_err);

  str_free(&sql_str);
  if (rc != SQLITE_OK)
  {
    die2("sql error: ", sql_err); /* Exit */
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
        str_append_text(&sql_str, " and ident isnull or ident = ''");

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
    die2("sql error: ", sql_err);
    return 0;
  }

  if (ipvalid)
  {
    vsf_db_add_session(p_sess);
    update_last_login(uid);
    return 1;
  }
#endif

  return 0;
}

/* Private methods ----------------------------------------------------------*/

static void
set_errmsg(const char* errmsg)
{
  strncpy(s_errmsg, errmsg, sizeof(s_errmsg));
  s_errmsg[sizeof(s_errmsg) - 1] = '\0';
}


static void
calc_md5(const char* data, char* hash, const int len)
{
	md5_state_t state;
	md5_byte_t  digest[16];
	int         di;

  assert(len >= 33);

  /* Calculate md5 hash of the password */
	md5_init(&state);
	md5_append(&state, (const md5_byte_t*) data, strlen(data));
	md5_finish(&state, digest);
  memset(hash, 0, len);
	for (di = 0; di < 16; ++di)
  {
    if (di * 2 + 2 < len)
      sprintf(hash + di * 2, "%02x", digest[di]);
  }
}
