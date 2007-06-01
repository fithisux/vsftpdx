#include "builddefs.h"

#ifdef VSF_BUILD_LUA

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "utility.h"
#include "str.h"
#include "sysstr.h"
#include "sysutil.h"

// External declaration, inits the sqlite/lua interface
int luaopen_sqlite3(lua_State * L);

// Table for exported sqlite related functions
static const luaL_reg s_sqlite3_methods[] = {
  {"init", luaopen_sqlite3 },
  {0, 0}
};

/* the Lua interpreter */
static lua_State* L = NULL;
static struct mystr scriptpath_str = INIT_MYSTR;
static struct mystr welcome_str;

void 
vsf_lua_open()
{
  str_getcwd(&scriptpath_str);
  str_append_text(&scriptpath_str, "/scripts/");

	/* initialize Lua */
	L = lua_open();

	/* load Lua base libraries */
	luaL_openlibs(L);

  luaL_register(L, "libsqlite3", s_sqlite3_methods);
	
	/* Open the sqlite library */
  luaopen_sqlite3(L);
}

void
vsf_lua_close()
{
	/* cleanup Lua */
	lua_close(L);    
}


void
vsf_lua_welcome(struct mystr* p_text_str)
{
	int result;
	const char filename[] = "welcome.lua";
	
	if (L == NULL)
    die("Lua script engine not initialized.");

  /* Remember the working directory */
  struct mystr cwd_str = INIT_MYSTR;
  str_getcwd(&cwd_str);
  
  /* Change to the script directory */
  str_chdir(&scriptpath_str); 
  
  /* Execute the script */
  result = luaL_dofile(L, filename);
	if (result != 0)
	{
    die2("Unable to run welcome script: ", lua_tostring(L,-1));
  }
	  
	/* Get the function result from the stack */
  const char* text = lua_tostring(L, lua_gettop(L));
	str_alloc_text(p_text_str, text);

  /* Change back to the working directory */  
  str_chdir(&cwd_str);
}



int luaadd ( int x, int y )
{
	int sum;

	/* the function name */
	lua_getglobal(L, "add");

	/* the first argument */
	lua_pushnumber(L, x);

	/* the second argument */
	lua_pushnumber(L, y);

	/* call the function with 2
	   arguments, return 1 result */
	lua_call(L, 2, 1);

	/* get the result */
	sum = (int)lua_tointeger(L, -1);
	lua_pop(L, 1);

	return sum;
}

#endif
