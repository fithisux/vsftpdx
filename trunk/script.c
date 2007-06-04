#include "builddefs.h"

#ifdef VSF_BUILD_LUA

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "utility.h"
#include "str.h"
#include "sysstr.h"
#include "sysutil.h"
#include "tunables.h"

static int s_strings_copied = 0;


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
  if (L != NULL)
    return;

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
  if (L == NULL)
    return;
    
	/* cleanup Lua */
	lua_close(L);    
}

static int
run_script(const char* p_filename)
{
	int result;
	
	if (L == NULL)
    die("Lua script engine not initialized.");

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

}

/* Tables mapping setting names to runtime variables */
/* Boolean settings */
static struct parseconf_bool_setting
{
  const char* p_setting_name;
  int* p_variable;
}
parseconf_bool_array[] =
{
  { "anonymous_enable", &tunable_anonymous_enable },
  { "local_enable", &tunable_local_enable },
  { "pasv_enable", &tunable_pasv_enable },
  { "port_enable", &tunable_port_enable },
  { "chroot_local_user", &tunable_chroot_local_user },
  { "write_enable", &tunable_write_enable },
  { "anon_upload_enable", &tunable_anon_upload_enable },
  { "anon_mkdir_write_enable", &tunable_anon_mkdir_write_enable },
  { "anon_other_write_enable", &tunable_anon_other_write_enable },
  { "chown_uploads", &tunable_chown_uploads },
  { "connect_from_port_20", &tunable_connect_from_port_20 },
  { "xferlog_enable", &tunable_xferlog_enable },
  { "dirmessage_enable", &tunable_dirmessage_enable },
  { "anon_world_readable_only", &tunable_anon_world_readable_only },
  { "async_abor_enable", &tunable_async_abor_enable },
  { "ascii_upload_enable", &tunable_ascii_upload_enable },
  { "ascii_download_enable", &tunable_ascii_download_enable },
  { "one_process_model", &tunable_one_process_model },
  { "xferlog_std_format", &tunable_xferlog_std_format },
  { "pasv_promiscuous", &tunable_pasv_promiscuous },
  { "deny_email_enable", &tunable_deny_email_enable },
  { "chroot_list_enable", &tunable_chroot_list_enable },
  { "setproctitle_enable", &tunable_setproctitle_enable },
  { "text_userdb_names", &tunable_text_userdb_names },
  { "ls_recurse_enable", &tunable_ls_recurse_enable },
  { "log_ftp_protocol", &tunable_log_ftp_protocol },
  { "guest_enable", &tunable_guest_enable },
  { "userlist_enable", &tunable_userlist_enable },
  { "userlist_deny", &tunable_userlist_deny },
  { "use_localtime", &tunable_use_localtime },
  { "check_shell", &tunable_check_shell },
  { "hide_ids", &tunable_hide_ids },
  { "listen", &tunable_listen },
  { "port_promiscuous", &tunable_port_promiscuous },
  { "passwd_chroot_enable", &tunable_passwd_chroot_enable },
  { "no_anon_password", &tunable_no_anon_password },
  { "tcp_wrappers", &tunable_tcp_wrappers },
  { "use_sendfile", &tunable_use_sendfile },
  { "force_dot_files", &tunable_force_dot_files },
  { "listen_ipv6", &tunable_listen_ipv6 },
  { "dual_log_enable", &tunable_dual_log_enable },
  { "syslog_enable", &tunable_syslog_enable },
  { "background", &tunable_background },
  { "virtual_use_local_privs", &tunable_virtual_use_local_privs },
  { "session_support", &tunable_session_support },
  { "download_enable", &tunable_download_enable },
  { "dirlist_enable", &tunable_dirlist_enable },
  { "chmod_enable", &tunable_chmod_enable },
  { "secure_email_list_enable", &tunable_secure_email_list_enable },
  { "run_as_launching_user", &tunable_run_as_launching_user },
  { "no_log_lock", &tunable_no_log_lock },
  { "ssl_enable", &tunable_ssl_enable },
  { "allow_anon_ssl", &tunable_allow_anon_ssl },
  { "force_local_logins_ssl", &tunable_force_local_logins_ssl },
  { "force_local_data_ssl", &tunable_force_local_data_ssl },
  { "ssl_sslv2", &tunable_sslv2 },
  { "ssl_sslv3", &tunable_sslv3 },
  { "ssl_tlsv1", &tunable_tlsv1 },
  { "tilde_user_enable", &tunable_tilde_user_enable },
  { "force_anon_logins_ssl", &tunable_force_anon_logins_ssl },
  { "force_anon_data_ssl", &tunable_force_anon_data_ssl },
  { "mdtm_write", &tunable_mdtm_write },
  { "lock_upload_files", &tunable_lock_upload_files },
  { "pasv_addr_resolve", &tunable_pasv_addr_resolve },
  { "sqlite_enable", &tunable_sqlite_enable },
  { "sqlite_log", &tunable_sqlite_log },
  { "calc_crc32", &tunable_calc_crc32 },
  { "ident_check_enable", &tunable_ident_check_enable },
  { "stealth_mode", &tunable_stealth_mode },
  { "sqlite_acl", &tunable_sqlite_acl },
  { "credit_enable", &tunable_credit_enable },
  { "show_infoline", &tunable_show_infoline },
  { "lua_enable", &tunable_lua_enable },
  { 0, 0 }
};

static struct parseconf_uint_setting
{
  const char* p_setting_name;
  unsigned int* p_variable;
}
parseconf_uint_array[] =
{
  { "accept_timeout", &tunable_accept_timeout },
  { "connect_timeout", &tunable_connect_timeout },
  { "local_umask", &tunable_local_umask },
  { "anon_umask", &tunable_anon_umask },
  { "ftp_data_port", &tunable_ftp_data_port },
  { "idle_session_timeout", &tunable_idle_session_timeout },
  { "data_connection_timeout", &tunable_data_connection_timeout },
  { "pasv_min_port", &tunable_pasv_min_port },
  { "pasv_max_port", &tunable_pasv_max_port },
  { "anon_max_rate", &tunable_anon_max_rate },
  { "local_max_rate", &tunable_local_max_rate },
  { "listen_port", &tunable_listen_port },
  { "max_clients", &tunable_max_clients },
  { "file_open_mode", &tunable_file_open_mode },
  { "max_per_ip", &tunable_max_per_ip },
  { "trans_chunk_size", &tunable_trans_chunk_size },
  { "delay_failed_login", &tunable_delay_failed_login },
  { "delay_successful_login", &tunable_delay_successful_login },
  { "max_login_fails", &tunable_max_login_fails },
  { "ident_check_timeout", &tunable_ident_check_timeout },
  { 0, 0 }
};

static struct parseconf_str_setting
{
  const char* p_setting_name;
  const char** p_variable;
}
parseconf_str_array[] =
{
  { "secure_chroot_dir", &tunable_secure_chroot_dir },
  { "ftp_username", &tunable_ftp_username },
  { "chown_username", &tunable_chown_username },
  { "xferlog_file", &tunable_xferlog_file },
  { "vsftpd_log_file", &tunable_vsftpd_log_file },
  { "message_file", &tunable_message_file },
  { "nopriv_user", &tunable_nopriv_user },
  { "ftpd_banner", &tunable_ftpd_banner },
  { "banned_email_file", &tunable_banned_email_file },
  { "chroot_list_file", &tunable_chroot_list_file },
  { "pam_service_name", &tunable_pam_service_name },
  { "guest_username", &tunable_guest_username },
  { "userlist_file", &tunable_userlist_file },
  { "anon_root", &tunable_anon_root },
  { "local_root", &tunable_local_root },
  { "banner_file", &tunable_banner_file },
  { "pasv_address", &tunable_pasv_address },
  { "listen_address", &tunable_listen_address },
  { "user_config_dir", &tunable_user_config_dir },
  { "listen_address6", &tunable_listen_address6 },
  { "cmds_allowed", &tunable_cmds_allowed },
  { "hide_file", &tunable_hide_file },
  { "deny_file", &tunable_deny_file },
  { "user_sub_token", &tunable_user_sub_token },
  { "email_password_file", &tunable_email_password_file },
  { "rsa_cert_file", &tunable_rsa_cert_file },
  { "dsa_cert_file", &tunable_dsa_cert_file },
  { "ssl_ciphers", &tunable_ssl_ciphers },
  { "rsa_private_key_file", &tunable_rsa_private_key_file },
  { "dsa_private_key_file", &tunable_dsa_private_key_file },
  { 0, 0 }
};

static void
copy_string_settings(void)
{
  const struct parseconf_str_setting* p_str_setting = parseconf_str_array;
  while (p_str_setting->p_setting_name != 0)
  {
    if (*p_str_setting->p_variable != 0)
    {
      *p_str_setting->p_variable =
          vsf_sysutil_strdup(*p_str_setting->p_variable);
    }
    p_str_setting++;
  }
}

void
vsf_lua_load_config(const char* p_filename, int errs_fatal)
{
  int result;
  
	if (L == NULL)
    die("Lua script engine not initialized.");

  /* Export global symbols */
  lua_pushinteger(L, 0);
  lua_setglobal(L, "NO");
  lua_pushinteger(L, 0);
  lua_setglobal(L, "FALSE");
  lua_pushinteger(L, 1);
  lua_setglobal(L, "YES");
  lua_pushinteger(L, 1);
  lua_setglobal(L, "TRUE");
  
  /* Execute the script */
  result = luaL_dofile(L, p_filename);

  if (result != 0)
  {
    if (errs_fatal)
    {
      die2("Unable to read configuration: ", lua_tostring(L,-1));
    }  
  }
  
  if (!s_strings_copied)
  {
    s_strings_copied = 1;
    /* A minor hack to make sure all strings are malloc()'ed so we can free
     * them at some later date. Specifically handles strings embedded in the
     * binary.
     */
    copy_string_settings();
  }
  
  
  /* Get string settings */
  const struct parseconf_str_setting* p_str_setting = parseconf_str_array;
  while (p_str_setting->p_setting_name != 0)
  {   
    const char*  p_key   = (const char*) p_str_setting->p_setting_name;
    const char** p_value = p_str_setting->p_variable;

    /* Tell lua to put the global variable on the stack */
    lua_getglobal(L, p_key);
    
    /* Check the variable and get the value */
    if (lua_isstring(L, -1))
    {
      *p_value = vsf_sysutil_strdup(lua_tostring(L, -1));
    }
    else      
    {
      lua_pop(L, -1);
    }
    
    printf("%s = %s\n", p_key, *p_value);   
       
    p_str_setting++;    
  }
      
    
  /* Get boolean settings */    
  const struct parseconf_bool_setting* p_bool_setting = parseconf_bool_array;
  while (p_bool_setting->p_setting_name != 0)
  {
    const char* p_key   = (const char*) p_bool_setting->p_setting_name;
    int*        p_value = p_bool_setting->p_variable;

    /* Tell lua to put the global variable on the stack */
    lua_getglobal(L, p_key);
    
    /* Check the variable and get the value */
    if (lua_isstring(L, -1))
    {
      struct mystr value_str = INIT_MYSTR;
      str_alloc_text(&value_str, lua_tostring(L, -1));
  
      /* Got it */
      str_upper(&value_str);
      if (str_equal_text(&value_str, "YES") ||
          str_equal_text(&value_str, "TRUE") ||
          str_equal_text(&value_str, "1"))
      {
        *p_value = 1;
      }
      else if (str_equal_text(&value_str, "NO") ||
               str_equal_text(&value_str, "FALSE") ||
               str_equal_text(&value_str, "0"))
      {
        *p_value = 0;
      }
      else if (errs_fatal)
      {
        die2("bad bool value in config file for: ", p_key);
      }
      
    }
    else    
    {
      lua_pop(L, -1);
    }
    
    printf("%s = %d\n", p_key, *p_value);
    
    p_bool_setting++;
  }
  
   
  /* Get integer settings */
  const struct parseconf_uint_setting* p_uint_setting = parseconf_uint_array;
  while (p_uint_setting->p_setting_name != 0)
  {
    const char*   p_key   = (const char*) p_uint_setting->p_setting_name;
    unsigned int* p_value = p_uint_setting->p_variable;

    /* Tell lua to put the global variable on the stack */
    lua_getglobal(L, p_key);
    
    /* Check the variable and get the value */
    if (lua_isnumber(L, -1))
    {
      *p_value = (unsigned int) lua_tointeger(L, -1);    
    }
    else
    {
      printf("%s NO NUMBER\n", p_key);
      
      lua_pop(L, -1);
    }
    
    printf("%s = %d\n", p_key, *p_value);
    
    p_uint_setting++;    
  }      
}


/* Demo */
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
