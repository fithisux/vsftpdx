#ifndef VSF_SCRIPT_H
#define VSF_SCRIPT_H

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"


lua_State* vsf_lua_getstate();
void vsf_lua_open();
void vsf_lua_close();
void vsf_lua_welcome();
void vsf_lua_register_hooks();

int vsf_lua_site_command(const struct mystr* p_command_str, 
                          int* p_result_code, struct mystr* p_result_str);

#endif /* VSF_SCRIPT_H */
