Check out the [vsftpd homepage](http://vsftpd.beasts.org/#features) for the inherited features.

### Database for virtual users ###
If the configuration option _sqlite\_enable=YES_ is set, the server will handle
the users authentication during the login phase using a local SQLite database.
The default name for this database is _site.db_. The included script _createdb.sh_
can be used to create a new default database. (1)

### Log to database ###
If the configuration option _sqlite\_log=YES_ is set, the server will write all log
entries to the SQLite database (table _vsf\_log_) instead of text files. (1)

### Stealth mode ###
If the configuration option _stealth\_mode=YES_ is set, the server will drop
any incoming connection if the remote IP address does not match any IP mask in the
database without any message to the client. (1)

### Cygwin support ###
Using [cygwin](http://www.cygwin.com) it is now possible to run this version vsftpd
on Windows too.

### Optional IPv6 ###
To compile vsftpdx on cygwin and older UNIX systems which do not support IPv6 the
new build option _VSF\_BUILD\_IPV6_ can be used to disable the IPv6 code.

### Ident check ###
Set the configuration option _ident\_check\_enable=YES_ to enable the ident checks
(RFC 1413 compatible) during the login phase. (1)

### SITE WHO command ###
The new command _SITE WHO_ shows a list of all connected clients. The database is used
to store the session information. (1)

(1) Requires SQLite support, which is enabled using the definition _#define VSF\_BUILD\_SQLITE_ in _builddefs.h_ during compile time.