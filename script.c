#include "builddefs.h"

#ifdef VSF_BUILD_LUA

#include "utility.h"
#include "str.h"
#include "sysstr.h"
#include "sysutil.h"
#include "tunables.h"
#include "script.h"

// Local functions
static int run_script(const char* p_filename);

// External declaration, inits the sqlite/lua interface
int luaopen_sqlite3(lua_State * L);

// Table for exported sqlite related functions
static const luaL_reg s_sqlite3_methods[] = {
  {"init", luaopen_sqlite3 },
  {0, 0}
};

/* the Lua interpreter */
static lua_State* L = NULL;
static struct mystr s_initpath_str = INIT_MYSTR;

lua_State*
vsf_lua_getstate()
{
  return L;  
}

void 
vsf_lua_open()
{
  if (L != NULL)
    return;

  str_getcwd(&s_initpath_str);

	/* Initialize Lua */
	L = lua_open();

	/* Load Lua base libraries */
	luaL_openlibs(L);

	/* Register the luaopen_sqlite3 function for Lua as libsqlite3:init().
   * Lua will call the function when the sqlite3.lua script is required
   * by another scripts.
   */
  luaL_register(L, "libsqlite3", s_sqlite3_methods); 
}

void
vsf_lua_close()
{
  if (L == NULL)
    return;
    
	/* cleanup Lua */
	lua_close(L);
  L = NULL;    
}


void
vsf_lua_register_hooks()
{
  run_script("hooks.lua"); 
}

void
vsf_lua_welcome(struct mystr* p_text_str)
{

	int result;
  const char filename[] = "welcome.lua";
	
  result = run_script(filename);	  

	if (result != 0)
	{
    die2("Unable to run welcome script: ", lua_tostring(L,-1));
  }
	  
	/* Get the function result from the stack */
  const char* text = lua_tostring(L, lua_gettop(L));
	str_alloc_text(p_text_str, text);
  lua_pop(L, 1);
}


int 
vsf_lua_site_command(const struct mystr* p_command_str, 
                     const struct mystr* p_arg_str,
                     int* p_result_code, struct mystr* p_result_str)
{
  lua_getglobal(L, "vsf_site_command");
  if (!lua_isfunction(L, -1))   
    return 1;
    
  lua_pushstring(L, str_getbuf(p_command_str));
  lua_pushstring(L, str_getbuf(p_arg_str));
  lua_call(L, 2, 2); /* 2 params, 2 return values */

  int stacksize = lua_gettop(L);

  /* Get result code (first result value) */
  if (!lua_isnumber(L, -2))
    return 1;
  *p_result_code = lua_tointeger(L, -2);

  /* Get result string (second result value) */
  if (!lua_isstring(L, -1))
    return 1;    
  str_alloc_text(p_result_str, lua_tostring(L, -1));

  /* Remove to entries from the stack */
  lua_pop(L, 2);
  
  return 0;
}


static int
run_script(const char* p_filename)
{
	int result;
	struct mystr scriptpath_str = INIT_MYSTR;
	
	if (L == NULL)
    die("Lua script engine not initialized.");

  if (vsf_sysutil_strlen(tunable_script_dir) > 0)
  {  
    if (tunable_script_dir[0] != '/')
    {
      /* Relative path */
      str_append_str(&scriptpath_str, &s_initpath_str);
      str_append_text(&scriptpath_str, "/");
    }

    str_append_text(&scriptpath_str, tunable_script_dir);  
  }

  /* Remember the working directory */
  struct mystr cwd_str = INIT_MYSTR;
  str_getcwd(&cwd_str);
  
  
  /* Change to the script directory */
  
  str_chdir(&scriptpath_str); 
  
  /* Execute the script */
  result = luaL_dofile(L, p_filename);

  /* Change back to the working directory */  
  str_chdir(&cwd_str);
  
  return result;
}


#endif
