
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

#define TCH_MAXLEN_SQL    255
#define TCH_MAXLEN_ERRMSG 255
#define TCH_MAX_BUSYTRIES 3

/* Static variables ---------------------------------------------------------*/

/* SQLite */
static sqlite3*      s_db_handle               = NULL;
static sqlite3_stmt* s_check_auth_stmt         = NULL;
static sqlite3_stmt* s_check_host_stmt         = NULL;
static sqlite3_stmt* s_check_file_stmt         = NULL;
static sqlite3_stmt* s_get_credit_stmt         = NULL;
static sqlite3_stmt* s_update_credit_stmt      = NULL;
static sqlite3_stmt* s_get_credit_section_stmt = NULL;
static sqlite3_stmt* s_get_ratio_stmt          = NULL;
static sqlite3_stmt* s_update_last_login_stmt  = NULL;
static sqlite3_stmt* s_log_append_stmt         = NULL;
static int           s_busy_count              = 0;
static int           s_step                    = 1;

/* The Lua interpreter */
static lua_State*    s_lua_handle              = NULL;
static char*         s_initpath                = NULL;

static char          s_errmsg[TCH_MAXLEN_ERRMSG]   = "";


// External declaration, inits the sqlite/lua interface
int luaopen_sqlite3(lua_State * L);

// Table for exported sqlite related functions
static const luaL_reg s_sqlite3_methods[] = {
  {"init", luaopen_sqlite3 },
  {0, 0}
};


/* Private function declarations --------------------------------------------*/

/* Sets the static error text */
static void set_errmsg();

/* Calculates an MD5 sum */
static void calc_md5(const char* data, char* hash, const int len);

/* Updates the last login time of the user in the database */
static int update_last_login(int uid);


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
  
  
  /* Initialize Lua */
  s_lua_handle= lua_open();
  
  /* Load Lua base libraries */
  luaL_openlibs(s_lua_handle);
  
  /* Register the luaopen_sqlite3 function for Lua as libsqlite3:init().
   * Lua will call the function when the sqlite3.lua script is required
   * by another scripts.
   */
  luaL_register(s_lua_handle, "libsqlite3", s_sqlite3_methods); 
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
  
  if (s_lua_handle != NULL)
  {
    lua_close(s_lua_handle);
    s_lua_handle = NULL;  
  }
}


const char* tch_errmsg()
{
  return s_errmsg;      
}


int tch_check_auth(struct tch_session* session, const char* username, 
                   const char* password, const char* host, const char* ident)
{
  int rc = 0, step = 1, busycount = 0, uid = -1, hostvalid = 0;
  char* sql_err = 0;
  static char passhash[32 + 1]; /* 128bit MD5 + terminating 0 */
  const char* p_tail = NULL;

  static char sql_auth[] =
    "SELECT id FROM vsf_user WHERE enabled = 1 AND name = ?"
    " AND (password = ? OR password ISNULL)";
    
  static char sql_host[] = 
    "SELECT COUNT(*) FROM vsf_ipmask WHERE user_id = ? AND ? GLOB mask"
    " AND (ident ISNULL OR ident = ?)";

  if (username == NULL || strlen(username) == 0 || 
      host == NULL || strlen(host) == 0)
  {
    return TCH_AUTH_ERR_PARAM;
  }

  /* Calculate password hash */
  if (password == NULL || strlen(password) == 0)
  {
    passhash[32] = '\0';
  }
  else
  {
    calc_md5(password, passhash, sizeof(passhash));
  }
           
  /* Prepare statement */           
  sqlite3_stmt* s = s_check_auth_stmt; /* Shortcut */
  if (s == NULL)
  {
    rc = sqlite3_prepare_v2(s_db_handle, sql_auth, -1, &s, &p_tail);
    if (rc != SQLITE_OK) goto ERR_DB;
    s_check_auth_stmt = s;
  }
  
  /* Bind parameters */
  rc = sqlite3_bind_text(s, 1, username, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_text(s, 2, passhash, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
      
  /* Execute the statement */
  while (step)
  {
    rc = sqlite3_step(s);
    switch (rc)
    {
      case SQLITE_BUSY:    /*We must try again, but not forever.*/
        if (busycount++ > TCH_MAX_BUSYTRIES) goto ERR_DB;
        sleep(0);  /*For a gentler poll.*/
        break;  
      case SQLITE_DONE:    /*Success, leave the loop */
        step = 0;
        break;  
      case SQLITE_ROW:     /*A row is ready.*/
        uid = sqlite3_column_int(s, 0);
        break;  
      default:
        goto ERR_DB;
    }
  }
  
  if (uid == -1)
  {
    return TCH_AUTH_BADPASS;      
  }
  
  session->uid = uid;
  
  /* Prepare statement */           
  s = s_check_host_stmt;
  if (s == NULL)
  {
    rc = sqlite3_prepare_v2(s_db_handle, sql_host, -1, &s, &p_tail);
    if (rc != SQLITE_OK) goto ERR_DB;
    s_check_host_stmt = s;
  }

  /* Bind parameters */  
  rc = sqlite3_bind_int(s, 1, session->uid);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_text(s, 2, host, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_text(s, 3, ident, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
  
  step = 1; busycount = 0;
  while (step)
  {
    rc = sqlite3_step(s);
    switch (rc)
    {
      case SQLITE_ROW:
        hostvalid = sqlite3_column_int(s, 0);
        break;
      case SQLITE_BUSY:
        if (busycount++ > TCH_MAX_BUSYTRIES) goto ERR_DB;
        sleep(0);
        break;                
      case SQLITE_DONE:
        step = 0;
        break;           
      default:
        goto ERR_DB;
    }
  }
  
  if (hostvalid)
  {
    if (!update_last_login(session->uid)) goto ERR_DB;
    return TCH_AUTH_OK;
  }
  
  return TCH_AUTH_BADHOST;
    
ERR_DB:
  set_errmsg(sqlite3_errmsg(s_db_handle));
  return TCH_AUTH_ERR_DB;
}



int tch_log_append(const struct tch_session* session, const int succeeded,
                   const int what, const char* message, const char* path, 
                   const long long duration, const long long size)
{
  int rc = 0, busycount = 0, step = 1;
  int pid = 0; /* TODO */
  char* sqlerr = NULL;
  const char* sqltail = NULL;
  char sqlbuf[] = 
    "INSERT INTO vsf_log (event_id, succeeded, user, remote_ip, pid, message,"
    " path, filesize, duration) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)";
   
  long delta_msec = 0;

  /* Prepare statement */           
  sqlite3_stmt* s = s_log_append_stmt;
  if (s == NULL)
  {
    rc = sqlite3_prepare_v2(s_db_handle, sqlbuf, -1, &s, &sqltail);
    if (rc != SQLITE_OK) goto ERR_DB;
    s_log_append_stmt = s;
  }
  
  /* Bind parameters */  
  int i = 1;
  rc = sqlite3_bind_int(s, i++, what);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_int(s, i++, succeeded);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_text(s, i++, session->username, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_text(s, i++, session->remotehost, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_int(s, i++, pid);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_text(s, i++, message, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_text(s, i++, path, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_int64(s, i++, size);
  if (rc != SQLITE_OK) goto ERR_DB;
  rc = sqlite3_bind_int64(s, i++, duration);
  if (rc != SQLITE_OK) goto ERR_DB;
  
  /* Execute statement */
  while (step)
  {
    rc = sqlite3_step(s);
    switch (rc)
    {
      case SQLITE_BUSY:
        if (busycount++ > TCH_MAX_BUSYTRIES) goto ERR_DB;
        sleep(0);
        break;                
      case SQLITE_DONE:
        step = 0;
        break;           
      default:
        goto ERR_DB;
    }
  }

  return TCH_LOG_OK;
  
ERR_DB:
  set_errmsg(sqlite3_errmsg(s_db_handle));
  return TCH_LOG_ERR_DB;  
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


static int
update_last_login(int uid)
{
  int rc = 0, step = 1, busycount = 0;
  char* sqlerr = NULL;
  const char* sqltail = NULL;
  static char sqlbuf[] = 
    "UPDATE vsf_user SET last_login = current_timestamp WHERE id = ?";

  /* Prepare statement */           
  sqlite3_stmt* s = s_update_last_login_stmt;
  if (s == NULL)
  {
    rc = sqlite3_prepare_v2(s_db_handle, sqlbuf, -1, &s, &sqltail);
    if (rc != SQLITE_OK) return 0;
    s_update_last_login_stmt = s;
  }
  else
  {
    sqlite3_reset(s);  
  }

  /* Bind parameters */  
  rc = sqlite3_bind_int(s, 1, uid);
  if (rc != SQLITE_OK) return 0;

  /* Execute statement */
  while (step)
  {
    rc = sqlite3_step(s);
    switch (rc)
    {
      case SQLITE_BUSY:
        if (busycount++ > TCH_MAX_BUSYTRIES) return 0;
        sleep(0);
        break;                
      case SQLITE_DONE:
        step = 0;
        break;           
      default:
        return 0;
    }
  }
 
  return 1;
}


static int 
run_script(const char* scriptdir, const char* filename)
{
	int result;
	char fullpath[TCH_MAXLEN_PATH];
	
	if (s_lua_handle == NULL)
  {
    set_errmsg("Lua script engine not initialized.");
    return 1;
  }

#ifdef FOO
  if (strlen(scriptdir) > 0)
  {  
      if (scriptdir[0] != '/' && scriptdir[0] != '~')
      {
        /* Relative path */
        snprintf(fullpath, sizeof(fullpath) "%s/%s", s_initpath, scriptdir);
        fullpath[sizeof(fullpath) -1] = '\0';
      }
   }


  /* Remember the working directory */
  struct mystr cwd_str = INIT_MYSTR;
  str_getcwd(&cwd_str);
  
  
  /* Change to the script directory */
  
  str_chdir(&scriptpath_str); 
  
  /* Execute the script */
  result = luaL_dofile(L, filename);

  /* Change back to the working directory */  
  str_chdir(&cwd_str);
#endif 
  return result;
  
}
