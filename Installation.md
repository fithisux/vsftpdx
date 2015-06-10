### Install required packages ###
The following packages are required to compile and execute the program:

**Ubuntu/Debian Linux**
  * libc-dev
  * libssl-dev
  * libsqlite3-dev
  * libcap-dev
  * sqlite3

**Cygwin**
  * gcc-core
  * make
  * openssl
  * openssl-devel
  * sqlite3 (libraries and sqlite3.exe are included in lib/sqlite3/cygwin)

### Build ###
Edit _builddefs.h_ with a text editor and set the compilation options you want. Run _make_ to compile the program.

### Create a new database ###
Use the include script _createdb.sh_ or run the following command manually _sqlite3 site.db < createdb.sql_. This creates a new database with the name _site.db_. The current version of vsftpd expects the file to be in the same directory as the executable.

### Edit the configuration ###
Edit the included file _vsftpd.conf_ with a text editor and set the options you like.

### Create an SSL certificate (optional) ###
```
openssl req -x509 -nodes -days 7300 -newkey rsa:2048 \
   -keyout ./site.pem -out ./site.pem
```

### Run ###
_./vsftpd ./vsftpd.conf_

The default password for the _root_ account is "vsftpd".

### Create users ###
Currently there are no SITE commands for user management, so you have to use an SQLite client to modify the database. The easiest way is to use a graphical tool like SQLite Administrator. Check out the following example if you want to use the command line client.

```
$ sqlite3 ./site.db
sqlite> insert into vsf_user (name) values ('MyUser');
sqlite> insert into vsf_ipmaks (user_id, mask) values (1, '127.0.0.1');
```