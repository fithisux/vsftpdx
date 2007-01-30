/*
 * Part of Very Secure FTPd
 * Licence: GPL v2
 * Author: Chris Evans
 * access.c
 *
 * Routines to do very very simple access control based on filenames.
 */

#include "access.h"
#include "ls.h"
#include "tunables.h"
#include "str.h"
#include "db.h"

int
vsf_access_check_file(const struct vsf_session* p_sess,
                      const struct mystr* p_filename_str,
                      enum EVSFFileAccess what)
{
  static struct mystr s_access_str;

  if (tunable_sqlite_acl)
  {
    /* Use the permissions from the database */
    return vsf_db_check_file(p_sess, p_filename_str, what);
  }

  if (!tunable_deny_file)
  {
    return 1;
  }
  if (str_isempty(&s_access_str))
  {
    str_alloc_text(&s_access_str, tunable_deny_file);
  }
  if (vsf_filename_passes_filter(p_filename_str, &s_access_str))
  {
    return 0;
  }
  else
  {
    struct str_locate_result loc_res =
      str_locate_str(p_filename_str, &s_access_str);
    if (loc_res.found)
    {
      return 0;
    }
  }
  return 1;
}

int
vsf_access_check_file_visible(const struct vsf_session* p_sess,
                              const struct mystr* p_filename_str)
{
  static struct mystr s_access_str;
  
  if (tunable_sqlite_acl)
  {
    /* Use the permissions from the database */
    return vsf_db_check_file(p_sess, p_filename_str, kVSFFileView);
  }
  

  if (!tunable_hide_file)
  {
    return 1;
  }
  if (str_isempty(&s_access_str))
  {
    str_alloc_text(&s_access_str, tunable_hide_file);
  }
  if (vsf_filename_passes_filter(p_filename_str, &s_access_str))
  {
    return 0;
  }
  else
  {
    struct str_locate_result loc_res =
      str_locate_str(p_filename_str, &s_access_str);
    if (loc_res.found)
    {
      return 0;
    }
  }
  return 1;
}

