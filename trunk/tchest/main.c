#include <stdio.h>
#include "tchest.h"

int main(int argc, char** argv)
{
  char buf[255];
  struct tch_session s;
  int rc;

  printf("TC test\n");
  /* fgets(buf, sizeof(buf), stdin); */
  
  tch_open("../site.db", "../scripts");
  
  if (argc == 6 && strncmp(argv[1], "auth", 4) == 0)
  {
    rc = tch_check_auth(&s, argv[2], argv[3], argv[4], argv[5]);
    if (rc == TCH_AUTH_OK)
      printf("Auth OK\n");
    else
      printf("Auth error: %d\n", rc);
  }
  
  if (argc == 2 && strncmp(argv[1], "log", 3) == 0)
  {
    rc = tch_log_append(&s, 1, TCH_LOG_UPLOAD, "File upped", "/foo/bar", 1, 1);
    if (rc == TCH_LOG_OK)
      printf("Log OK\n");
    else
      printf("Log error: %s\n", tch_errmsg());
  }
  
  tch_close();
}
