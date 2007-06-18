
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <sqlite3.h>

#include "tchest.h"


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
static lua_State*    s_lua                     = NULL;
static char*         s_initpath                = NULL;

static char s_errmsg[1024];


/* Static functions ---------------------------------------------------------*/

static void set_errmsg();

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
  if (s_lua == NULL)
    return;
    
	/* cleanup Lua */
	lua_close(s_lua);
  s_lua = NULL;    
  
}

static void
set_errmsg(const char* errmsg)
{
  strncpy(&s_errmsg, errmsg, sizeof(s_errmsg));
  s_errmsg[sizeof(s_errmsg) - 1] = '\0';  
}

