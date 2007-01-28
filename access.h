#ifndef VSF_ACCESS_H
#define VSF_ACCESS_H

#include "session.h"

struct mystr;

enum EVSFFileAccess
{
  kVSFFileView = 1, /* See the file */
  kVSFFileGet,      /* Download a file */
  kVSFFilePut,      /* Upload a file */  
  kVSFFileResume,   /* Resume an upload */
  kVSFFileDelete,   /* Delete a file */
  kVSFFileRename,   /* Rename a file */
  kVSFFileChmod,    /* Change local filesystem permissions */
  kVSFDirView,      /* See directory */
  kVSFDirList,      /* List directory content */
  kVSFDirChange,    /* Change into the directory */
  kVSFDirCreate,    /* Create sub directory */
  kVSFDirDelete,    /* Delete sub directory */
};

/* vsf_access_check_file()
 * PURPOSE
 * Check whether the current session has permission to access the given
 * filename.
 * PARAMETERS
 * p_sess          - the current session
 * p_filename_str  - the filename to check access for
 * what            - the type of file access requested
 * RETURNS
 * Returns 1 if access is granted, otherwise 0.
 */
int vsf_access_check_file(const struct vsf_session* p_sess,
                          const struct mystr* p_filename_str,
                          enum EVSFFileAccess what);

/* vsf_access_check_file_visible()
 * PURPOSE
 * Check whether the current session has permission to view the given
 * filename in directory listings.
 * PARAMETERS
 * p_sess          - the current session
 * p_filename_str  - the filename to check visibility for
 * RETURNS
 * Returns 1 if the file should be visible, otherwise 0.
 */
int vsf_access_check_file_visible(const struct vsf_session* p_sess,
                                  const struct mystr* p_filename_str);

#endif /* VSF_ACCESS_H */

