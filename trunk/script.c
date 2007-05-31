#include "builddefs.h"

#ifdef VSF_BUILD_LUA

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "utility.h"
#include "str.h"
#include "sysstr.h"

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
	
	if (L == NULL)
    die("Lua script engine not initialized.");
  	
  /* load the script */
  struct mystr script_str = INIT_MYSTR;
  str_append_str(&script_str, &scriptpath_str);
  str_append_text(&script_str, "welcome.lua");
  FILE* f = fopen(str_getbuf(&script_str), "r");
  if (f == NULL)
    die("Unable to open script file");
  else
    fclose(f);

  result = luaL_dofile(L, str_getbuf(&script_str));
	if (result != 0)
	  die2("Unable to run welcome script: ", str_getbuf(&script_str));
	  
	const char* text = lua_tostring(L, lua_gettop(L));
	str_alloc_text(p_text_str, text);		
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
