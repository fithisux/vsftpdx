
/* rfc1413 does an attempt at an ident query to a client. 
 * Originally written by Wietse Venema, 
 * rewritten by Bob Beck <beck@openbsd.org>,
 * rewritten by Robert Hahn for vsftpd.
 */

#include "builddefs.h"
#include "port/porting_junk.h"
#include "sysutil.h"
#include "str.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#define	IDENT_PORT	 113

/*
 * rfc1413, an rfc1413 client request for user name given a socket
 * structure, with a timeout in seconds on the whole operation.  On
 * success returns 0 and saves the username provided by remote ident daemon 
 * into "p_ident_str", stripping off any terminating CRLF, and terminating 
 * with a nul byte. Returns -1 on failure (timeout, remote daemon didn't 
 * answer, etc). 
 */

int
rfc1413(
  struct vsf_sysutil_sockaddr* p_remote_addr, 
  struct vsf_sysutil_sockaddr* p_local_addr, 
  struct mystr* p_ident_str, int ident_timeout_time)
{
	int s, gotit, retval;
	unsigned int i;
	char *cp;
	unsigned short remote_port;
	unsigned short local_port;
	unsigned short remote_port_answer;
	unsigned short local_port_answer;

	fd_set* readfds = NULL;
	fd_set* writefds = NULL;

  struct vsf_sysutil_sockaddr* p_remote_query_addr = NULL;
  struct vsf_sysutil_sockaddr* p_local_query_addr = NULL;
  
	char user[256];	 
	char tbuf[1024];	 
	size_t rsize, wsize;
	
	gotit = 0;
	s = -1;
	
	/* address family must be the same */
  if (vsf_sysutil_sockaddr_is_ipv6(p_remote_addr) !=
      vsf_sysutil_sockaddr_is_ipv6(p_local_addr))
    return -1;

  remote_port = vsf_sysutil_sockaddr_get_port(p_remote_addr);
  local_port  = vsf_sysutil_sockaddr_get_port(p_local_addr);

  /* Create new socket */
  if (vsf_sysutil_sockaddr_is_ipv6(p_remote_addr))
    s = vsf_sysutil_get_ipv6_sock(); /* Dies on error */
  else
		s = vsf_sysutil_get_ipv4_sock(); /* Dies on error */

  vsf_sysutil_activate_reuseaddr(s);
	
	/*
	 * Bind the local and remote ends of the query socket to the same
	 * IP addresses as the connection under investigation. We go
	 * through all this trouble because the local or remote system
	 * might have more than one network address. The IDENT etc.
	 * client sends only port numbers; the server takes the IP
	 * addresses from the query socket.
	 */
  vsf_sysutil_sockaddr_clone(&p_local_query_addr, p_local_addr);
	vsf_sysutil_sockaddr_set_port(p_local_query_addr, 0);
	vsf_sysutil_sockaddr_clone(&p_remote_query_addr, p_remote_addr);
	vsf_sysutil_sockaddr_set_port(p_remote_query_addr, IDENT_PORT);
	
  /* Bind socket */
  retval = vsf_sysutil_bind(s, p_local_query_addr);
  if (vsf_sysutil_retval_is_error(retval))
		goto out;
		
  /* Connect to the remote host using a timeout value */
  retval = vsf_sysutil_connect_timeout(s, p_remote_query_addr, 
                                       ident_timeout_time);
  if (vsf_sysutil_retval_is_error(retval))
		goto out;

	/* We are connected,  build an ident query and send it. */ 
	
	rsize = howmany(s+1, NFDBITS);
	readfds = calloc(rsize, sizeof(fd_mask));
	if (readfds == NULL) 
		goto out;

	wsize = howmany(s+1, NFDBITS);
	writefds = calloc(wsize, sizeof(fd_mask));
	if (writefds == NULL) 
		goto out;
		
	/* Create string with remote and local port */
  snprintf(tbuf, sizeof(tbuf), "%u,%u\r\n", ntohs(remote_port),
	    ntohs(local_port));
	    
	i = 0;

  struct timeval timeout;
  timeout.tv_sec = ident_timeout_time;
  timeout.tv_usec = 0;	

	while (i < strlen(tbuf)) 
  { 
		int j;

		memset(writefds, 0, wsize * sizeof(fd_mask));
		FD_SET(s, writefds);
		
    /* Wait until the socket is ready */
    do 
    { 
			j = select(s + 1, NULL, writefds, NULL, &timeout);
		} 
    while (j == -1 && (errno == EAGAIN || errno == EINTR));

		if (j == -1 || j == 0)
			goto out;

		if (FD_ISSET(s, writefds)) 
    {
			j = write(s, tbuf + i, strlen(tbuf + i));
			if (j == -1 && errno != EAGAIN && errno != EINTR)
				goto out;
			if  (j != -1) 
				i += j;
		} 
    else 
			goto out;
	} 
	
	/* Read the answer back. */
	i = 0;
	tbuf[0] = '\0';
	while ((cp = strchr(tbuf, '\n')) == NULL && i < sizeof(tbuf) - 1) 
  {
		int j;

		memset(readfds, 0, rsize * sizeof(fd_mask));
		FD_SET(s, readfds);
		
    /* Wait until the socket is ready, abort on timeout */
    do 
    { 
			j = select(s + 1, readfds, NULL, NULL, &timeout);
		} 
    while ( j == -1 && (errno == EAGAIN || errno == EINTR ));
		
    if (j == -1 || j == 0)
			goto out;
		
    if (FD_ISSET(s, readfds)) 
    {
			j = read(s, tbuf + i, sizeof(tbuf) - 1 - i);
			if ((j == -1 && errno != EAGAIN && errno != EINTR) || j == 0) 
				goto out;
			
      if  (j != -1) 
				i += j;
			tbuf[i] = '\0';
		} 
    else
			goto out;
	}
	
	if ((sscanf(tbuf,"%hu , %hu : USERID :%*[^:]:%255s", 
      &remote_port_answer, &local_port_answer, user) == 3) &&
	    (ntohs(remote_port) == remote_port_answer) &&
	    (ntohs(local_port) == local_port_answer)) {
		if ((cp = strchr(user, '\r')) != NULL)
			*cp = '\0';
		gotit = 1;
	}

out:
	/* Clean up */
  if (readfds != NULL)
		free(readfds);
	if (writefds != NULL)
		free(writefds);
	if (p_remote_query_addr != NULL)
	  vsf_sysutil_sockaddr_clear(&p_remote_query_addr);
	if (p_local_query_addr != NULL)
	  vsf_sysutil_sockaddr_clear(&p_local_query_addr);
		
	if (s != -1) 
		vsf_sysutil_close(s);

	if (gotit) 
  {
		str_alloc_text(p_ident_str, user);
		return 0 ;
	}
	return -1;
}
