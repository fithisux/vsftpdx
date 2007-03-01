#include "site.h"
#include "str.h"
#include "session.h"
#include "db.h"
#include "banner.h"
#include "ftpcodes.h"

void 
vsf_site_user(struct vsf_session* p_sess, struct mystr* p_arg_str)
{
  static struct mystr s_args_str;
  static struct mystr s_syntax_str = INIT_MYSTR;
  
  if (str_isempty(&s_syntax_str))
  {
    str_alloc_text(&s_syntax_str, 
      "Syntax: SITE USER ADD <name>\r\n"
      "        SITE USER REMOVE <name>\r\n");
  }
  
  /* ADD, REMOVE, DISABLE, ENABLE, LIST */
  
  str_split_char(p_arg_str, &s_args_str, ' ');
  str_upper(p_arg_str);
  
  if (str_isempty(&s_args_str))
  {
    vsf_banner_write(p_sess, &s_syntax_str, FTP_BADCMD);
    return;
  } 
  
  if (str_equal_text(p_arg_str, "ADD"))
  {
    if (!str_contains_space(&s_args_str) &&
      !str_contains_unprintable(&s_args_str))
    {
      vsf_db_add_user(p_sess, &s_args_str);
    }
  }
  else if (str_equal_text(p_arg_str, "REMOVE"))
  {
    
  }
  else
  {
    vsf_banner_write(p_sess, &s_syntax_str, FTP_BADCMD);
    return;
  }  
}
