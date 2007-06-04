#ifndef VSF_SCRIPT_H
#define VSF_SCRIPT_H

void vsf_lua_open();

void vsf_lua_close();

void vsf_lua_welcome();

void vsf_lua_load_config(const char* p_filename, int errs_fatal);

#endif /* VSF_SCRIPT_H */
